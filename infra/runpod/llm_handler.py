"""RunPod Serverless Handler — substitui AWS Bedrock.

LLM inference via open-source models on RunPod Serverless (LLaMA 3.3 70B).
Custo: ~$200/mes vs Bedrock $850/mes (77% cheaper).

Modelos disponiveis via RunPod Serverless:
- meta-llama/Llama-3.3-70B-Instruct (volume tier, equiv. Haiku)
- meta-llama/Llama-3.3-70B-Instruct (reasoning, equiv. Sonnet)
- mistralai/Mistral-7B-Instruct (economico, equiv. Haiku light)
"""

from __future__ import annotations

import json, os, time
import httpx

RUNPOD_API_KEY = os.environ.get("RUNPOD_API_KEY", "")
RUNPOD_ENDPOINT_ID = os.environ.get("RUNPOD_ENDPOINT_ID", "")
RUNPOD_VLLM_URL = os.environ.get("RUNPOD_VLLM_URL", "")


def call_llm(
    system_prompt: str,
    user_message: str,
    model: str = "llama-70b",
    max_tokens: int = 4096,
    temperature: float = 0.1,
) -> tuple[str, str, int]:
    """Call LLM via RunPod Serverless (substituto Bedrock invoke).

    Returns (response_text, model_used, processing_time_ms).
    """
    start = time.monotonic()

    # Route: PCI/PII data → vLLM Pod (dedicated GPU)
    # Non-PCI data → Serverless endpoint (cheaper)
    if RUNPOD_VLLM_URL:
        # Direct vLLM pod (PCI data)
        url = f"{RUNPOD_VLLM_URL}/v1/chat/completions"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        headers = {"Authorization": f"Bearer {RUNPOD_API_KEY}", "Content-Type": "application/json"}
    else:
        # Serverless endpoint (non-PCI, cheaper)
        url = f"https://api.runpod.ai/v2/{RUNPOD_ENDPOINT_ID}/runsync"
        payload = {
            "input": {
                "system_prompt": system_prompt,
                "user_message": user_message,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
        }
        headers = {"Authorization": f"Bearer {RUNPOD_API_KEY}", "Content-Type": "application/json"}

    resp = httpx.post(url, json=payload, headers=headers, timeout=120)
    resp.raise_for_status()
    data = resp.json()

    processing_time_ms = int((time.monotonic() - start) * 1000)

    # Parse response
    if RUNPOD_VLLM_URL:
        # Direct vLLM format
        response_text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    else:
        # Serverless wrapper format
        response_text = data.get("output", {}).get("content", data.get("output", ""))

    return response_text, model, processing_time_ms
