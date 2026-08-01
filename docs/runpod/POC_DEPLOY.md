# RunPod POC Deploy — Passo a Passo (2 minutos)

![RunPod](https://img.shields.io/badge/RunPod-POC_Deploy-7b42bc)
![Custo](https://img.shields.io/badge/custo-hora-00ff88)

> **Tempo:** 2 minutos | **Custo:** ~$0.16/hr (RTX A5000) | **API Key:** configurada

---

## 1. Deploy GPU Pod (via Console)

```
1. Acesse https://console.runpod.io/deploy
2. Selecione GPU: RTX A5000 (24GB, $0.16/hr) — mais barata >=24GB
3. Template: runpod/pytorch:2.4.0-py3.11-cuda12.4.1
4. Container Disk: 25 GB
5. Volume: 30 GB
6. Expose port: 8000 (HTTP)
7. Clique "Deploy"
```

## 2. Instalar vLLM no Pod (1 comando)

```bash
# Via Web Terminal no console RunPod:
pip install vllm transformers fastapi uvicorn httpx
python -m vllm.entrypoints.openai.api_server \
  --model mistralai/Mistral-7B-Instruct-v0.3 \
  --max-model-len 4096 \
  --port 8000 --host 0.0.0.0
```

## 3. Testar Inferencia

```bash
curl http://<POD_IP>:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"mistral","messages":[{"role":"user","content":"Say ZTK POC success"}],"max_tokens":20}'
```

## 4. Integrar com Z.T.K.

No `.env`:
```
RUNPOD_VLLM_URL=http://<POD_IP>:8000
```

O L7 router ja esta configurado para usar `RUNPOD_VLLM_URL` automaticamente.

## 5. Parar o Pod (economizar)

```bash
# No console RunPod: Pod → Stop
# Ou via API:
# mutation { podStop(input: {podId: "<ID>"}) { id } }
```

**Importante:** Parar o pod quando nao estiver usando. Custo = $0 quando parado.
