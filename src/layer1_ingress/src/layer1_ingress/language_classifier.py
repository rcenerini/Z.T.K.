"""L1.02 — Language & Artifact Classifier Agent.

Deterministic classifier based on file extensions and path heuristics.
No LLM, no enry binary. Maps to shared.schemas.finding.Language enum.
"""

from __future__ import annotations

from shared.schemas.finding import Language
from shared.utils.fail_closed import Defaults, fail_closed
from shared.utils.structlog_setup import get_logger

logger = get_logger(__name__)


# Extension to language mapping (deterministic, auditable)
EXTENSION_MAP: dict[str, Language] = {
    ".py": Language.PYTHON,
    ".pyi": Language.PYTHON,
    ".pyx": Language.PYTHON,
    ".java": Language.JAVA,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".ts": Language.TYPESCRIPT,
    ".tsx": Language.TYPESCRIPT,
    ".go": Language.GO,
    ".rs": Language.RUST,
    ".cpp": Language.CPP,
    ".cc": Language.CPP,
    ".cxx": Language.CPP,
    ".c": Language.C,
    ".h": Language.C,
    ".cs": Language.CSHARP,
    ".php": Language.PHP,
    ".rb": Language.RUBY,
    ".kt": Language.KOTLIN,
    ".kts": Language.KOTLIN,
    ".swift": Language.SWIFT,
    ".dart": Language.DART,
    ".scala": Language.SCALA,
    ".sc": Language.SCALA,
    ".tf": Language.TERRAFORM,
    ".tfvars": Language.TERRAFORM,
    ".hcl": Language.TERRAFORM,
    ".dockerfile": Language.DOCKERFILE,
    ".yaml": Language.KUBERNETES,
    ".yml": Language.KUBERNETES,
    ".toml": Language.OTHER,
    ".json": Language.OTHER,
    ".xml": Language.OTHER,
    ".md": Language.OTHER,
    ".txt": Language.OTHER,
    ".cfg": Language.OTHER,
    ".ini": Language.OTHER,
    ".env": Language.OTHER,
    ".lock": Language.OTHER,
    ".gradle": Language.OTHER,
    ".pom": Language.OTHER,
    ".Makefile": Language.OTHER,
    ".Rakefile": Language.OTHER,
    ".sh": Language.OTHER,
    ".bash": Language.OTHER,
    ".zsh": Language.OTHER,
    ".ps1": Language.OTHER,
    ".bat": Language.OTHER,
    ".sql": Language.OTHER,
    ".graphql": Language.OTHER,
    ".proto": Language.OTHER,
}

# Filename-based classification (no extension)
FILENAME_MAP: dict[str, Language] = {
    "Dockerfile": Language.DOCKERFILE,
    "Makefile": Language.OTHER,
    "CMakeLists.txt": Language.CPP,
    "BUILD": Language.OTHER,
    "WORKSPACE": Language.OTHER,
    "Cargo.toml": Language.RUST,
    "go.mod": Language.GO,
    "go.sum": Language.GO,
    "package.json": Language.JAVASCRIPT,
    "tsconfig.json": Language.TYPESCRIPT,
    "requirements.txt": Language.PYTHON,
    "setup.py": Language.PYTHON,
    "setup.cfg": Language.PYTHON,
    "Pipfile": Language.PYTHON,
    "pyproject.toml": Language.PYTHON,
    "Gemfile": Language.RUBY,
    "Rakefile": Language.RUBY,
    "pom.xml": Language.JAVA,
    "build.gradle": Language.KOTLIN,
    "build.gradle.kts": Language.KOTLIN,
    "settings.gradle": Language.KOTLIN,
    "composer.json": Language.PHP,
    "Cargo.lock": Language.RUST,
    "Package.swift": Language.SWIFT,
    "Podfile": Language.SWIFT,
    "pubspec.yaml": Language.DART,
    "build.sbt": Language.SCALA,
}


@fail_closed(fallback_value=Language.OTHER, fallback_message="Language classification failed")
def classify_file(file_path: str, content_hint: str = "") -> Language:
    """Classify a file's programming language.

    Uses: (1) filename match, (2) extension match, (3) content hint fallback.
    Deterministic — same input always produces same output.
    """
    from pathlib import Path

    path = Path(file_path)

    # Step 1: Exact filename match
    if path.name in FILENAME_MAP:
        return FILENAME_MAP[path.name]

    # Step 2: Extension match
    suffix = path.suffix.lower()
    if suffix in EXTENSION_MAP:
        return EXTENSION_MAP[suffix]

    # Step 3: Double extension (e.g., .test.py, .spec.ts)
    if len(path.suffixes) >= 2:
        double_suffix = "".join(path.suffixes[-2:]).lower()
        if double_suffix in EXTENSION_MAP:
            return EXTENSION_MAP[double_suffix]

    # Step 4: Content hint (e.g., shebang line)
    if content_hint:
        hint_lower = content_hint.lower()
        if "python" in hint_lower or "#!/usr/bin/env python" in hint_lower:
            return Language.PYTHON
        if "node" in hint_lower or "#!/usr/bin/env node" in hint_lower:
            return Language.JAVASCRIPT
        if "#!/bin/bash" in hint_lower or "#!/bin/sh" in hint_lower:
            return Language.OTHER

    return Language.OTHER


def classify_batch(file_paths: list[str]) -> dict[str, Language]:
    """Classify multiple files in batch."""
    return {fp: classify_file(fp) for fp in file_paths}


def get_sast_agents_for_language(language: Language) -> list[str]:
    """Return the SAST agent IDs that should analyse a given language."""
    agent_map: dict[Language, list[str]] = {
        Language.PYTHON: ["L2.01-bandit", "L2.02-semgrep-python"],
        Language.JAVA: ["L2.03-spotbugs", "L2.04-codeql-java"],
        Language.JAVASCRIPT: ["L2.05-eslint", "L2.06-semgrep-js"],
        Language.TYPESCRIPT: ["L2.05-eslint", "L2.06-semgrep-js"],
        Language.GO: ["L2.07-gosec", "L2.08-codeql-go"],
        Language.CPP: ["L2.09-cppcheck", "L2.10-codeql-cpp"],
        Language.C: ["L2.09-cppcheck", "L2.10-codeql-cpp"],
        Language.RUST: ["L2.11-clippy"],
        Language.CSHARP: ["L2.12-roslyn"],
        Language.PHP: ["L2.13-psalm"],
        Language.RUBY: ["L2.14-brakeman"],
        Language.KOTLIN: ["L2.15-detekt"],
        Language.SWIFT: ["L2.16-swiftlint"],
        Language.TERRAFORM: ["L2.24-checkov", "L2.25-tfsec"],
        Language.DOCKERFILE: ["L2.26-hadolint"],
        Language.KUBERNETES: ["L2.27-kubesec"],
        Language.OTHER: [],
        Language.DART: [],
        Language.SCALA: [],
    }
    return agent_map.get(language, [])
