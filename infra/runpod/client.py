"""RunPod Client — POC wrapper para API RunPod.

Gerencia endpoints serverless e pods GPU.
API key via env var RUNPOD_API_KEY (NUNCA hardcoded).
"""

from __future__ import annotations

import json, os, time
import httpx

API_KEY = os.environ.get("RUNPOD_API_KEY", "")
GRAPHQL_URL = "https://api.runpod.io/graphql"
SERVERLESS_URL = "https://api.runpod.ai/v2"


def _query(query: str, variables: dict | None = None) -> dict:
    """Execute GraphQL query against RunPod API."""
    resp = httpx.post(
        GRAPHQL_URL,
        json={"query": query, "variables": variables or {}},
        headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    if "errors" in data:
        raise RuntimeError(f"RunPod API: {data['errors'][0]['message']}")
    return data["data"]


def get_account_info() -> dict:
    """Return account info: user ID."""
    return _query("query { myself { id } }")["myself"]


def list_gpu_types() -> list[dict]:
    """List available GPU types with pricing."""
    result = _query("""
        query {
            gpuTypes {
                id displayName memoryInGb
                securePrice communityPrice
            }
        }
    """)
    return result.get("gpuTypes", [])


def create_serverless_template(
    name: str = "ztk-llama-8b",
    image: str = "runpod/worker-vllm:latest",
) -> dict:
    """Create a serverless template (endpoint) for LLM inference.

    This is the cheapest option for POC — pay per use, scale to zero.
    """
    result = _query("""
        mutation($input: SaveEndpointInput!) {
            saveEndpoint(input: $input) {
                id name templateId aiApiType
            }
        }
    """, {
        "input": {
            "name": name,
            "templateId": "runpod/worker-vllm:latest",
            "aiApiType": "chat",
            "gpuTypes": "NVIDIA L4",
            "idleTimeout": 5,
            "scalerType": "QUEUE_DELAY",
            "scalerValue": 4,
            "workersMin": 0,
            "workersMax": 3,
            "env": {
                "MODEL_NAME": "meta-llama/Llama-3.3-70B-Instruct",
            },
        }
    })
    return result.get("saveEndpoint", {})


def test_inference(prompt: str = "Say 'ZTK POC successful' in one word.") -> dict:
    """Test inference via RunPod serverless. Requires endpoint ID in env."""
    endpoint_id = os.environ.get("RUNPOD_ENDPOINT_ID", "")
    if not endpoint_id:
        return {"error": "RUNPOD_ENDPOINT_ID not set. Deploy an endpoint first."}

    resp = httpx.post(
        f"{SERVERLESS_URL}/{endpoint_id}/runsync",
        json={
            "input": {
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 20,
                "temperature": 0.1,
            }
        },
        headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
        timeout=60,
    )
    return resp.json()
