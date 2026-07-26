"""Prompt builder — assembles structured prompts from schema, SSVC tree, and finding context.

The fixed context (schema + SSVC tree) supports Anthropic prompt caching.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import CopilotSettings, get_settings
from .models import AmbiguitySignal, FindingContext


class PromptBuilder:
    """Builds structured Anthropic Messages API prompts for ATTEND-tier analysis."""

    def __init__(self, settings: CopilotSettings | None = None) -> None:
        self._settings = settings or get_settings()
        self._schema: dict[str, Any] = {}
        self._loaded: bool = False

    def _load_schema(self) -> None:
        if self._loaded:
            return
        schema_path = self._settings.prompt_schema_path
        if schema_path.exists():
            self._schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self._loaded = True

    @property
    def fixed_context(self) -> str:
        """Build the fixed-cacheable context (SSVC tree + severity pisos + CWE categories)."""
        self._load_schema()
        if not self._schema:
            return self._default_fixed_context()

        ssvc = self._schema.get("ssvc_tree", {})
        piso = self._schema.get("severity_piso", {})
        cwe_cat = self._schema.get("cwe_categories", {})

        parts: list[str] = [
            "You are a security copilot analysing a vulnerability finding (ATTEND tier).",
            "",
            "## SSVC Decision Tree Context",
            f"- Exploitation: {json.dumps(ssvc.get('exploitation', {}))}",
            f"- Exposure: {json.dumps(ssvc.get('exposure', {}))}",
            f"- Mission Impact: {json.dumps(ssvc.get('mission_impact', {}))}",
            "",
            "## Non-Negotiable Severity Floors",
        ]
        for domain, floor in piso.items():
            parts.append(f"- {domain.upper()}: {floor}")

        parts.extend([
            "",
            "## CWE Categories",
        ])
        for cat, cwes in cwe_cat.items():
            parts.append(f"- {cat}: {', '.join(cwes)}")

        parts.extend([
            "",
            "## Instructions",
            "1. Analyse whether the finding is a TRUE POSITIVE or likely FALSE POSITIVE.",
            "2. Assess severity considering the SSVC tree AND non-negotiable floors.",
            "3. NEVER suggest lowering severity below the applicable floor.",
            "4. Provide a concise remediation recommendation.",
            "5. Flag any ambiguity signals (missing context, version conflicts, etc.).",
            "6. Output MUST be valid JSON matching the expected schema.",
        ])
        return "\n".join(parts)

    def build_analysis_prompt(self, finding: FindingContext) -> tuple[str, str]:
        """Build the full prompt for ATTEND analysis.

        Returns (system_prompt, user_message) for Anthropic Messages API.
        """
        self._load_schema()

        system_prompt = self.fixed_context

        user_parts: list[str] = [
            "## Finding to Analyse",
            f"Finding ID: {finding.finding_id}",
            f"Source: {finding.source}",
            f"Severity (tool): {finding.severity.value}",
            f"CWE IDs: {', '.join(finding.cwe_ids)}",
            f"File: {finding.file_path}:{finding.line_number}",
            f"Language: {finding.language or 'unknown'}",
            f"CVSS Vector: {finding.cvss_vector or 'not provided'}",
            f"Decision Score: {finding.score}/10",
            f"Decision Tier: {finding.decision_tier.value}",
            "",
            "## Description",
            finding.description,
            "",
            "## Evidence",
            finding.evidence,
            "",
            "## Related Findings",
            (
                ", ".join(str(fid) for fid in finding.related_findings)
                if finding.related_findings
                else "none"
            ),
            "",
            "## Output Format (JSON)",
            "{",
            '  "is_true_positive": true|false,',
            '  "confidence": "HIGH"|"MEDIUM"|"LOW",',
            '  "severity_assessment": "P0"|"P1"|"P2"|"P3"|"P4",',
            '  "severity_justification": "string (min 30 chars)",',
            '  "remediation_summary": "string (min 20 chars)",',
            '  "remediation_steps": ["step1", "step2"],',
            '  "piso_applied": ["PCI"|"LGPD"|"ANTIFRAUDE"|null],',
            '  "ambiguity_signals": [',
            '    {"type": "VERSION_CONFLICT"|"MISSING_CONTEXT"|...,',
            '     "description": "string",',
            '     "severity_impact": "string",',
            '     "suggested_action": "string"}',
            "  ],",
            '  "requires_sonnet_escalation": true|false',
            "}",
        ]

        return system_prompt, "\n".join(user_parts)

    def parse_response(
        self, raw_response: str, finding: FindingContext, model_used: str, processing_time_ms: int
    ) -> list[AmbiguitySignal]:
        """Parse LLM JSON response into structured signals.

        Returns ambiguity signals extracted from the response.
        """
        try:
            data = json.loads(raw_response)
        except json.JSONDecodeError:
            return [
                AmbiguitySignal(
                    signal_type="MISSING_CONTEXT",  # type: ignore[arg-type]  # safest default
                    description="LLM response was not valid JSON",
                    severity_impact="Unable to assess",
                    suggested_action="Manual review required",
                    confidence="LOW",  # type: ignore[arg-type]
                )
            ]

        signals: list[AmbiguitySignal] = []
        for raw_signal in data.get("ambiguity_signals", []):
            if not isinstance(raw_signal, dict):
                continue
            try:
                # Normalise: JSON may use "type" instead of "signal_type"
                if "type" in raw_signal and "signal_type" not in raw_signal:
                    raw_signal["signal_type"] = raw_signal.pop("type")
                # Provide default confidence if missing
                if "confidence" not in raw_signal:
                    raw_signal["confidence"] = "LOW"
                signals.append(AmbiguitySignal(**raw_signal))
            except Exception:
                continue  # Skip malformed signal, don't block analysis

        return signals

    @staticmethod
    def _default_fixed_context() -> str:
        """Fallback fixed context when prompt_schema.json is not available."""
        return (
            "You are a security copilot analysing a vulnerability finding (ATTEND tier).\n\n"
            "## Non-Negotiable Severity Floors\n"
            "- PCI (CHD/PAN processing): P1\n"
            "- LGPD (sensitive personal data): P1\n"
            "- ANTIFRAUDE (auth/transaction/balance): P0\n\n"
            "## Instructions\n"
            "1. Analyse whether the finding is a TRUE POSITIVE or likely FALSE POSITIVE.\n"
            "2. Assess severity considering SSVC tree AND non-negotiable floors.\n"
            "3. NEVER suggest lowering severity below the applicable floor.\n"
            "4. Provide a concise remediation recommendation.\n"
            "5. Flag any ambiguity signals (missing context, version conflicts, etc.).\n"
            "6. Output MUST be valid JSON matching the expected schema.\n"
        )
