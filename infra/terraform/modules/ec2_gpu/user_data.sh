#!/bin/bash
set -euo pipefail

# User data para EC2 GPU — setup vLLM
# Chamado no boot da instancia g5.xlarge

exec > >(tee /var/log/user-data.log) 2>&1

echo "[ZTK-vLLM] Iniciando setup em $(date)"

# Atualizar pacotes
yum update -y

# Instalar CUDA (driver ja vem na AMI g5, mas toolkit eh necessario)
yum install -y gcc gcc-c++ make git wget

# Instalar Miniconda
wget -q https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O /tmp/miniconda.sh
bash /tmp/miniconda.sh -b -p /opt/miniconda
export PATH="/opt/miniconda/bin:$PATH"
echo 'export PATH="/opt/miniconda/bin:$PATH"' >> /etc/profile.d/conda.sh

# Criar ambiente conda
conda create -n vllm python=3.12 -y
source /opt/miniconda/bin/activate vllm

# Instalar vLLM + dependencias
pip install --upgrade pip
pip install vllm transformers torch awscli

# Configurar AWS CLI (usa IAM role da instancia)
aws configure set region us-east-1

# Criar diretorio de modelos
mkdir -p /opt/models
cd /opt/models

# Download do modelo (via HuggingFace — requer token se gated)
# O token deve estar no Secrets Manager e ser lido aqui
# NOTA: Em producao, o modelo deve estar pre-baked na AMI ou no S3
# para evitar download a cada boot de spot instance

echo "[ZTK-vLLM] Modelo configurado: ${model_name}"

# Iniciar vLLM (API server)
# Em producao, usar systemd service
python -m vllm.entrypoints.openai.api_server \
  --model "${model_name}" \
  --tensor-parallel-size 1 \
  --max-model-len 8192 \
  --port 8000 \
  --host 0.0.0.0 \
  --api-key "${api_key}" &

echo "[ZTK-vLLM] vLLM iniciado em $(date)"

# Health check simples
sleep 60
curl -s http://localhost:8000/health || echo "Health check falhou"
