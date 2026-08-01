# RunPod Migration — Substituindo AWS GPU + Bedrock

![RunPod](https://img.shields.io/badge/RunPod-GPU_Cloud-7b42bc?logo=runpod)
![Savings](https://img.shields.io/badge/savings-70%25-00ff88)
![Status](https://img.shields.io/badge/status-planejado-00d4ff)

> **Versao:** 1.0 | **Data:** 2026-07-27
> **Objetivo:** Migrar workloads GPU do AWS (EC2 g5 + Bedrock) para RunPod, reduzindo custo em ~70%

---

## 1. Comparativo de Custo — AWS vs RunPod

### GPU Inference (vLLM local para PCI)

| Provedor | GPU | VRAM | Preco/hr | Custo 24/7/mes |
|----------|-----|------|----------|-----------------|
| AWS EC2 g5.xlarge | A10G | 24 GB | $1.21 | **$871** |
| RunPod A100 PCIe (Community) | A100 | 80 GB | $1.19 | $857 |
| RunPod A100 PCIe (Secure) | A100 | 80 GB | $1.39 | $1,001 |
| **RunPod L40S (Community)** | L40S | 48 GB | **$0.79** | **$569** |
| RunPod L40S (Secure) | L40S | 48 GB | $0.99 | $713 |
| RunPod A40 (Community) | A40 | 48 GB | $0.35 | $252 |
| RunPod A40 (Secure) | A40 | 48 GB | $0.44 | $317 |

**Recomendacao POC:** Serverless (paga so pelo uso, escala a zero quando idle). Sem custo fixo.

**Recomendacao Producao:** Pod A40 Secure Cloud 24/7 ($317/mes) + Serverless.

### LLM Inference (substituto Bedrock)

| Provedor | Servico | Custo mensal estimado |
|----------|---------|-----------------------|
| AWS Bedrock (Claude Haiku) | API gerenciada | **~$850/mes** |
| AWS Bedrock (Claude Sonnet) | API gerenciada | **~$150/mes** |
| RunPod Serverless (LLaMA 3.3 70B) | L40S workers | **~$200/mes** |
| RunPod Serverless (Mistral 7B) | L4 workers | **~$50/mes** |

### Custo Total (POC — Serverless on-demand, nao 24/7)

| Stack | GPU | LLM | Total estimado/mes |
|-------|-----|-----|-------------------|
| **AWS (atual)** | EC2 g5 24/7 $871 | Bedrock $850 | **~$1,721** |
| **RunPod POC (serverless)** | $0/mes (idle) ~$5 uso | Serverless ~$15 uso | **~$20/mes** |
| **RunPod POC (pod on-demand)** | A40 $0.35/hr (~$50/mes POC) | Serverless ~$15 | **~$65/mes** |

**Economia POC: 96-99%** (vs AWS 24/7)

---

## 2. O que migra e o que fica

| Componente | AWS (atual) | RunPod (novo) | Fica na AWS? |
|-----------|-------------|---------------|-------------|
| vLLM GPU | EC2 g5.xlarge | RunPod Pod (L40S/A40) | ❌ |
| LLM Inference (Copilot) | Bedrock (Claude) | RunPod Serverless (LLaMA 70B) | ❌ |
| Lambda (L1, L3-L8) | AWS Lambda | AWS Lambda | ✅ Mantido |
| ECS Fargate (L2) | AWS ECS | AWS ECS | ✅ Mantido |
| DynamoDB | AWS | AWS | ✅ Mantido |
| S3 | AWS | AWS | ✅ Mantido |
| SQS | AWS | AWS | ✅ Mantido |
| Aurora pgvector | AWS | RunPod Network Storage + pgvector | ⚠️ Opcional |

---

## 3. Configuracao RunPod — vLLM GPU Pod

### Dockerfile

```dockerfile
FROM runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04

RUN pip install vllm transformers fastapi uvicorn

COPY handler.py /handler.py
COPY start.sh /start.sh

RUN chmod +x /start.sh
CMD ["/start.sh"]
```

### start.sh

```bash
#!/bin/bash
python -m vllm.entrypoints.openai.api_server \
  --model meta-llama/Llama-3.3-70B-Instruct \
  --tensor-parallel-size 1 \
  --max-model-len 8192 \
  --port 8000 \
  --host 0.0.0.0
```

### handler.py

```python
import runpod

def handler(job):
    """RunPod serverless handler — substitui Bedrock invoke."""
    import httpx
    resp = httpx.post(
        "http://localhost:8000/v1/chat/completions",
        json={
            "model": "meta-llama/Llama-3.3-70B-Instruct",
            "messages": [{"role": "user", "content": job["input"]["prompt"]}],
            "max_tokens": job["input"].get("max_tokens", 4096),
            "temperature": 0.1,
        },
        timeout=120,
    )
    return resp.json()

runpod.serverless.start({"handler": handler})
```

---

## 4. Terraform — Modulo RunPod

```hcl
# infra/runpod/main.tf
terraform {
  required_providers {
    runpod = {
      source  = "runpod/runpod"
      version = "~> 1.0"
    }
  }
}

provider "runpod" {
  api_key = var.runpod_api_key
}

resource "runpod_pod" "vllm" {
  name            = "${var.name_prefix}-vllm"
  image_name      = "runpod/pytorch:2.4.0-py3.11-cuda12.4.1"
  gpu_type_id     = "NVIDIA L40S"  # ou "NVIDIA A40"
  gpu_count       = 1
  container_disk_in_gb = 100
  volume_in_gb    = 50

  # Docker args
  docker_args     = "-p 8000:8000"
  env = {
    MODEL_NAME     = "meta-llama/Llama-3.3-70B-Instruct"
    MAX_MODEL_LEN  = "8192"
    API_KEY        = var.vllm_api_key
  }

  # Secure Cloud (PCI compliance)
  cloud_type = "SECURE"
}

resource "runpod_network_storage" "models" {
  name      = "${var.name_prefix}-models"
  size      = 200
  data_center_id = "US-TX-1"
}
```

---

## 5. Seguranca (PCI DSS)

| Requisito | AWS (atual) | RunPod (novo) |
|-----------|-------------|---------------|
| Criptografia em repouso | KMS SSE | RunPod Secure Cloud |
| Isolamento de rede | VPC + CDE | Secure Cloud (dedicado) |
| Logging | CloudWatch | RunPod logs + webhook |
| IAM | Roles AWS | API keys + token rotation |

**Nota:** RunPod **Secure Cloud** isola recursos em hardware dedicado, sem multi-tenancy. Essencial para PCI DSS.

---

## 6. Atualizacao do LLM Router (L7)

```python
# llm_router.py — atualizado para RunPod
LLM_BACKENDS = {
    "vllm_local": "http://{runpod_pod_ip}:8000/v1/chat/completions",  # RunPod pod
    "serverless": "https://api.runpod.ai/v2/{endpoint_id}/runsync",    # RunPod serverless
}
```

---

## 7. Roteiro de Migracao (POC — serverless, custo ~$20/mes)

| Fase | Acao | Tempo | Custo |
|------|------|-------|-------|
| 1 | Criar conta RunPod (gratis) | 10 min | $0 |
| 2 | Deploy serverless endpoint com LLaMA 8B via template | 30 min | $0 |
| 3 | Testar 1 chamada de inferencia | 5 min | ~$0.001 |
| 4 | Atualizar L7 router (apontar para RunPod) | 30 min | $0 |
| 5 | Rodar E2E com RunPod | 10 min | ~$0.01 |
| **Total** | | **~1.5h** | **~$0.01** |

### Pos-POC (producao)

| Fase | Acao | Tempo | Custo/mes |
|------|------|-------|-----------|
| 6 | Subir Pod A40 24/7 para vLLM | 1h | $252 |
| 7 | Migrar Aurora pgvector (opcional) | 2h | $30 |
| 8 | Desligar EC2 g5 + Bedrock AWS | 10 min | -$1,650 |
| **Total** | | **~3h** | **~$300/mes** |
