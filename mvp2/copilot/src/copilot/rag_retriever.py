"""RAG retriever — stub implementation using local JSON index.

Future replacement: Aurora PostgreSQL + pgvector with cosine similarity.
The interface is designed to make the migration drop-in (swap implementation).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import CopilotSettings, get_settings
from .models import FindingContext


@dataclass
class RagDocument:
    """A single RAG-retrieved document."""
    doc_id: str
    cwe_ids: list[str]
    title: str
    summary: str
    severity_tendency: str
    remediation_pattern: str
    references: list[str] = field(default_factory=list)
    score: float = 0.0  # Relevance score (0-1)


class RagRetriever:
    """Retrieves relevant context documents for a given finding.

    Currently uses local JSON index with keyword matching.
    Future: Aurora PostgreSQL + pgvector with cosine similarity.
    """

    def __init__(self, settings: CopilotSettings | None = None) -> None:
        self._settings = settings or get_settings()
        self._documents: list[dict[str, Any]] = []
        self._loaded: bool = False

    def _load_index(self) -> None:
        if self._loaded:
            return
        index_path = self._settings.rag_index_path
        if index_path.exists():
            data = json.loads(index_path.read_text(encoding="utf-8"))
            self._documents = data.get("documents", [])
        self._loaded = True

    def retrieve(self, finding: FindingContext, max_docs: int | None = None) -> list[RagDocument]:
        """Retrieve relevant RAG documents for a finding.

        Matches by CWE ID overlap. Sorts by relevance score descending.
        """
        self._load_index()
        max_docs = max_docs or self._settings.rag_max_docs
        threshold = self._settings.rag_similarity_threshold

        scored: list[RagDocument] = []
        finding_cwes = set(finding.cwe_ids)

        for doc in self._documents:
            doc_cwes = set(doc.get("cwe_ids", []))
            overlap = finding_cwes & doc_cwes
            if not overlap:
                continue

            # Score = Jaccard similarity (overlap / union)
            union = finding_cwes | doc_cwes
            score = len(overlap) / len(union) if union else 0.0

            if score < threshold:
                continue

            scored.append(RagDocument(
                doc_id=doc["id"],
                cwe_ids=list(doc_cwes),
                title=doc["title"],
                summary=doc["summary"],
                severity_tendency=doc.get("severity_tendency", "unknown"),
                remediation_pattern=doc.get("remediation_pattern", ""),
                references=doc.get("references", []),
                score=score,
            ))

        # Sort by relevance descending, take top N
        scored.sort(key=lambda d: d.score, reverse=True)
        return scored[:max_docs]

    def format_context(self, documents: list[RagDocument]) -> str:
        """Format RAG documents into prompt context string."""
        if not documents:
            return "No relevant context documents found."

        parts: list[str] = [
            "## RAG Context (from knowledge base)",
            f"Retrieved {len(documents)} document(s):",
            "",
        ]
        for i, doc in enumerate(documents, 1):
            parts.extend([
                f"### [{i}] {doc.title} (score: {doc.score:.2f})",
                f"CWEs: {', '.join(doc.cwe_ids)}",
                f"Typical severity: {doc.severity_tendency}",
                f"Summary: {doc.summary}",
                f"Remediation pattern: {doc.remediation_pattern}",
                f"References: {', '.join(doc.references)}",
                "",
            ])
        return "\n".join(parts)

    @property
    def document_count(self) -> int:
        """Number of documents in the index (for metrics)."""
        self._load_index()
        return len(self._documents)
