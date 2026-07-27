"""L1.01 — Repo/Diff Ingestion Agent.

Read-only Git client. Receives repo URL + commit SHA, clones (shallow),
extracts diff, and produces a list of FileContext objects.
100% deterministic — no LLM.
"""

from __future__ import annotations

import hashlib
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from uuid import UUID

from shared.schemas.finding import Finding, FindingSeverity, FindingSource, FindingStatus, Language
from shared.utils.fail_closed import Defaults, fail_closed
from shared.utils.idempotency import generate_idempotency_key
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


@dataclass
class FileContext:
    """Single file extracted from a repo diff."""
    file_path: str
    language: Optional[str] = None
    content: str = ""
    patch: str = ""
    is_new: bool = False
    is_deleted: bool = False
    is_binary: bool = False
    lines_added: int = 0
    lines_removed: int = 0
    content_hash: str = ""

    def __post_init__(self) -> None:
        if self.content and not self.content_hash:
            self.content_hash = hashlib.sha256(self.content.encode()).hexdigest()


@dataclass
class IngestionResult:
    """Output of the ingestion agent."""
    repo_url: str
    commit_sha: str
    branch: str
    files: list[FileContext] = field(default_factory=list)
    total_lines_added: int = 0
    total_lines_removed: int = 0
    repo_languages: dict[str, float] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def ingest_diff(
    repo_url: str,
    commit_sha: str,
    branch: str = "main",
    tenant_id: str = "ztk-proj",
    max_file_size_kb: int = 500,
) -> IngestionResult:
    """Ingest a single commit diff from a Git repository.

    Uses git CLI (read-only, shallow clone). No credentials stored.
    Files larger than max_file_size_kb are skipped.

    Args:
        repo_url: Git repository URL (https or ssh).
        commit_sha: Full commit SHA to analyze.
        branch: Branch name (for metadata).
        tenant_id: Tenant identifier.
        max_file_size_kb: Skip files larger than this (DoS protection).

    Returns:
        IngestionResult with list of FileContext objects.
    """
    logger.info("ingestion_started", repo_url=repo_url[:80], commit=commit_sha[:8])

    result = IngestionResult(repo_url=repo_url, commit_sha=commit_sha, branch=branch)

    with tempfile.TemporaryDirectory(prefix="ztk-ingest-") as tmp_dir:
        repo_path = Path(tmp_dir) / "repo"

        try:
            # Shallow clone (depth=1, single commit)
            _run_git([
                "clone", "--depth=1", "--single-branch",
                "--branch", branch, repo_url, str(repo_path),
            ], timeout=120)
        except subprocess.TimeoutExpired:
            result.errors.append("Git clone timeout (>120s)")
            return result
        except subprocess.CalledProcessError as e:
            result.errors.append(f"Git clone failed: {e.stderr[:200] if e.stderr else str(e)}")
            return result

        try:
            # Get diff for the specific commit
            diff_output = _run_git(["diff", "--unified=5", f"{commit_sha}~1", commit_sha], cwd=repo_path)
        except (subprocess.CalledProcessError, RuntimeError):
            # First commit has no parent — use git show instead
            try:
                diff_output = _run_git(["show", "--format=", commit_sha], cwd=repo_path)
            except (subprocess.CalledProcessError, RuntimeError):
                # Complete failure — log and return empty result
                logger.error("git_diff_failed", commit=commit_sha[:8])
                result.errors.append(f"Could not get diff for commit {commit_sha[:8]}")
                return result

        # Parse diff into FileContext objects
        result.files = _parse_diff(diff_output, max_file_size_kb)
        result.total_lines_added = sum(f.lines_added for f in result.files)
        result.total_lines_removed = sum(f.lines_removed for f in result.files)

        # Detect repository languages
        result.repo_languages = _detect_languages(repo_path)

    logger.info(
        "ingestion_complete",
        files=len(result.files),
        lines_added=result.total_lines_added,
        lines_removed=result.total_lines_removed,
    )
    return result


def _run_git(args: list[str], cwd: Optional[Path] = None, timeout: int = 60) -> str:
    """Run a git command and return stdout. Raises on any error."""
    result = subprocess.run(
        ["git"] + args,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, args, result.stdout, result.stderr)
    return result.stdout


def _parse_diff(diff_text: str, max_size_kb: int) -> list[FileContext]:
    """Parse unified diff output into FileContext objects."""
    files: list[FileContext] = []
    current_file: Optional[FileContext] = None
    current_content: list[str] = []
    current_patch: list[str] = []
    lines_added = 0
    lines_removed = 0

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            # Save previous file
            if current_file is not None:
                current_file.content = "\n".join(current_content)
                current_file.patch = "\n".join(current_patch)
                current_file.lines_added = lines_added
                current_file.lines_removed = lines_removed
                # Skip binary files
                if not current_file.is_binary:
                    size_kb = len(current_file.content.encode()) / 1024
                    if size_kb <= max_size_kb:
                        files.append(current_file)

            # Start new file
            current_file = FileContext(file_path="")
            current_content = []
            current_patch = []
            lines_added = 0
            lines_removed = 0

        elif line.startswith("--- "):
            if current_file:
                current_file.file_path = line[6:] if line.startswith("--- a/") else line[4:]
        elif line.startswith("+++ "):
            if current_file:
                path = line[6:] if line.startswith("+++ b/") else line[4:]
                if path != "/dev/null":
                    current_file.file_path = path
        elif line.startswith("Binary files"):
            if current_file:
                current_file.is_binary = True
        elif line.startswith("new file"):
            if current_file:
                current_file.is_new = True
        elif line.startswith("deleted file"):
            if current_file:
                current_file.is_deleted = True
        elif line.startswith("@@"):
            current_patch.append(line)
        elif line.startswith("+"):
            current_content.append(line[1:])
            current_patch.append(line)
            lines_added += 1
        elif line.startswith("-"):
            current_patch.append(line)
            lines_removed += 1
        elif line.startswith(" "):
            current_content.append(line[1:])
            current_patch.append(line)

    # Save last file
    if current_file is not None and not current_file.is_binary:
        current_file.content = "\n".join(current_content)
        current_file.patch = "\n".join(current_patch)
        current_file.lines_added = lines_added
        current_file.lines_removed = lines_removed
        size_kb = len(current_file.content.encode()) / 1024
        if size_kb <= max_size_kb:
            files.append(current_file)

    return files


def _detect_languages(repo_path: Path) -> dict[str, float]:
    """Detect repository languages by file extension heuristic.
    Deterministic — no ML, no enry binary dependency.
    """
    extension_map: dict[str, str] = {
        ".py": "python", ".java": "java", ".js": "javascript", ".ts": "typescript",
        ".go": "go", ".rs": "rust", ".cpp": "cpp", ".c": "c", ".cs": "csharp",
        ".php": "php", ".rb": "ruby", ".kt": "kotlin", ".swift": "swift",
        ".tf": "terraform", ".hcl": "terraform", ".dockerfile": "dockerfile",
        ".yaml": "kubernetes", ".yml": "kubernetes", ".sh": "shell",
    }

    counts: dict[str, int] = {}
    total = 0

    for ext, lang in extension_map.items():
        count = len(list(repo_path.rglob(f"*{ext}")))
        if count > 0:
            counts[lang] = count
            total += count

    if total == 0:
        return {"unknown": 100.0}

    return {lang: round(count / total * 100, 1) for lang, count in counts.items()}
