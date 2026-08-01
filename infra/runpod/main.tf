# RunPod vLLM GPU Pod — substitui EC2 g5.xlarge
# Secure Cloud para PCI DSS compliance

terraform {
  required_providers {
    runpod = {
      source  = "runpod/runpod"
      version = "~> 1.0"
    }
  }
}

variable "name_prefix" { type = string }
variable "runpod_api_key" { type = string; sensitive = true }
variable "gpu_type" { type = string; default = "NVIDIA L40S" }
variable "gpu_count" { type = number; default = 1 }
variable "container_disk_gb" { type = number; default = 100 }
variable "volume_gb" { type = number; default = 50 }
variable "vllm_api_key" { type = string; sensitive = true }
variable "model_name" { type = string; default = "meta-llama/Llama-3.3-70B-Instruct" }
variable "max_model_len" { type = number; default = 8192 }

resource "runpod_pod" "vllm" {
  name                = "${var.name_prefix}-vllm-gpu"
  image_name          = "runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04"
  gpu_type_id         = var.gpu_type
  gpu_count           = var.gpu_count
  container_disk_in_gb = var.container_disk_gb
  volume_in_gb        = var.volume_gb
  cloud_type          = "SECURE"  # PCI DSS: dedicated hardware

  ports               = "8000/http"

  env = {
    MODEL_NAME    = var.model_name
    MAX_MODEL_LEN = var.max_model_len
    API_KEY       = var.vllm_api_key
  }

  # Script de inicializacao (vLLM + hardening basico)
  container_entrypoint = "/bin/bash"
  container_args       = "-c 'pip install vllm transformers fastapi uvicorn httpx && python -m vllm.entrypoints.openai.api_server --model ${var.model_name} --tensor-parallel-size 1 --max-model-len ${var.max_model_len} --port 8000 --host 0.0.0.0 --api-key ${var.vllm_api_key}'"
}

resource "runpod_network_storage" "models" {
  name           = "${var.name_prefix}-model-storage"
  size           = 200
  data_center_id = "US-TX-1"
}

output "pod_id" { value = runpod_pod.vllm.id }
output "pod_ip" { value = runpod_pod.vllm.pod_ip }
output "storage_id" { value = runpod_network_storage.models.id }
