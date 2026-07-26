"""Claude client — Bedrock runtime wrapper for Anthropic Claude 3.5 models.

Uses AWS Bedrock (boto3) via the Anthropic Messages API format.
NEVER hardcode credentials — uses default boto3 credential chain.

Model selection:
- Haiku (rutine ATTEND analysis) — fast, cheap, high volume
- Sonnet (ambiguity escalation) — deeper reasoning when Haiku is uncertain
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from .config import CopilotSettings, get_settings
from .models import CopilotAnalysis, FindingContext, Confidence


class ClaudeClient:
    """Client for Claude models via AWS Bedrock Runtime."""

    def __init__(self, settings: CopilotSettings | None = None) -> None:
        self._settings = settings or get_settings()
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client

        try:
            import boto3  # type: ignore[import-untyped]
            self._client = boto3.client(
                "bedrock-runtime",
                region_name=self._settings.bedrock_region,
                endpoint_url=self._settings.bedrock_endpoint_url,
            )
        except Exception:
            self._client = None
        return self._client

    def analyse(
        self,
        system_prompt: str,
        user_message: str,
        finding: FindingContext,
        prefer_model: Optional[str] = None,
    ) -> tuple[str, str, int]:
        """Send prompt to Claude and return the raw response text.

        Returns (response_text, model_used, processing_time_ms).

        Raises:
            RuntimeError: if Bedrock is unavailable and no mock is configured.
        """
        model_id = prefer_model or self._settings.bedrock_haiku_model
        start = time.monotonic()

        client = self._get_client()
        if client is None:
            raise RuntimeError(
                "Bedrock client unavailable. Set COPILOT_BEDROCK_REGION and ensure "
                "AWS credentials are configured."
            )

        # Anthropic Messages API via Bedrock
        body: dict[str, Any] = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": self._settings.bedrock_max_tokens,
            "temperature": self._settings.bedrock_temperature,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_message}
            ],
        }

        response = client.invoke_model(
            modelId=model_id,
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body),
        )

        response_body = json.loads(response["body"].read())
        processing_time_ms = int((time.monotonic() - start) * 1000)

        # Extract text from Claude response
        content = response_body.get("content", [])
        text_parts: list[str] = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block["text"])

        response_text = "\n".join(text_parts)

        if not response_text.strip():
            raise RuntimeError("Claude returned empty response")

        return response_text, model_id, processing_time_ms

    def escalate_to_sonnet(
        self,
        system_prompt: str,
        user_message: str,
        finding: FindingContext,
        signals_count: int,
    ) -> tuple[str, str, int]:
        """Escalate analysis to Sonnet when Haiku is uncertain.

        Only called when ambiguity_signals >= escalation_threshold.
        """
        user_message_with_context = (
            f"## ESCALATION — {signals_count} ambiguity signals detected by Haiku\n\n"
            f"{user_message}\n\n"
            "## Escalation Note\n"
            "A faster model flagged this finding as ambiguous. "
            "Provide a deeper analysis and resolve the ambiguity where possible. "
            "If the ambiguity cannot be resolved with available evidence, "
            "clearly state that HUMAN REVIEW is required."
        )
        return self.analyse(
            system_prompt=system_prompt,
            user_message=user_message_with_context,
            finding=finding,
            prefer_model=self._settings.bedrock_sonnet_model,
        )

    @property
    def available(self) -> bool:
        """Check if Bedrock client is available."""
        return self._get_client() is not None
