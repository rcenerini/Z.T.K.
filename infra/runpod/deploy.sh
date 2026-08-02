#!/bin/bash
# Z.T.K. RunPod Deploy — Gerencia pods GPU via API
# Uso: bash infra/runpod/deploy.sh [create|status|stop|destroy] [GPU_TYPE]
#
# Requer: RUNPOD_API_KEY no .env
# GPU Types: A5000(0.16/hr), 3090(0.22), A6000(0.33), A40(0.35), L40S(0.69)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Load .env
[ -f "$PROJECT_ROOT/.env" ] && source "$PROJECT_ROOT/.env"
: "${RUNPOD_API_KEY:?RUNPOD_API_KEY not set in .env}"
: "${RUNPOD_POD_ID:=}"

API="https://api.runpod.io/graphql"
GPU="${2:-NVIDIA RTX A5000}"
POD_NAME="ztk-poc-vllm"

gql() {
    local query="$1" vars="${2:-{}}"
    curl -s -X POST "$API" \
        -H "Authorization: Bearer $RUNPOD_API_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"query\": $(echo "$query" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read()))'), \"variables\": $vars}"
}

case "${1:-status}" in
    create)
        echo "🚀 Deploying GPU pod: $GPU ($POD_NAME)..."
        # Find GPU type ID
        GPU_ID=$(gql '{gpuTypes{id displayName communityPrice}}' | python3 -c "
import json,sys
data=json.load(sys.stdin)['data']['gpuTypes']
for g in data:
    if g['displayName']=='$GPU': print(g['id']); break
")
        if [ -z "$GPU_ID" ]; then echo "GPU $GPU not found"; exit 1; fi

        # Create pod
        RESULT=$(gql 'mutation(\$i:PodFindAndDeployOnDemandInput!){podFindAndDeployOnDemand(input:\$i){id name desiredStatus costPerHr machine{gpuDisplayName} runtime{ports{ip port isIpPublic}}}}' \
            "{\"i\":{\"cloudType\":\"COMMUNITY\",\"gpuCount\":1,\"volumeInGb\":30,\"containerDiskInGb\":25,\"minVcpuCount\":8,\"minMemoryInGb\":30,\"gpuTypeId\":\"$GPU_ID\",\"name\":\"$POD_NAME\",\"imageName\":\"runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04\",\"ports\":\"8000/http\",\"env\":{\"MODEL_NAME\":\"mistralai/Mistral-7B-Instruct-v0.3\"}}}")
        
        POD_ID=$(echo "$RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data']['podFindAndDeployOnDemand']['id'])")
        echo "POD_ID=$POD_ID" > "$PROJECT_ROOT/.env.runpod"
        echo "✅ Pod created: $POD_ID"
        echo "   GPU: $GPU"
        echo "   Cost: $(echo "$RESULT" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['podFindAndDeployOnDemand']['costPerHr'])")/hr"
        ;;

    status)
        if [ -z "$RUNPOD_POD_ID" ] && [ -f "$PROJECT_ROOT/.env.runpod" ]; then
            source "$PROJECT_ROOT/.env.runpod"
            RUNPOD_POD_ID="$POD_ID"
        fi
        if [ -z "${RUNPOD_POD_ID:-}" ]; then echo "No pod ID. Run 'deploy.sh create' first."; exit 1; fi
        gql "query(\$id:String!){pod(input:{podId:\$id}){id name desiredStatus runtime{uptimeInSeconds ports{ip port isIpPublic}}}}" "{\"id\":\"$RUNPOD_POD_ID\"}" | python3 -m json.tool
        ;;

    stop)
        if [ -z "${RUNPOD_POD_ID:-}" ]; then echo "Set RUNPOD_POD_ID or source .env.runpod"; exit 1; fi
        gql 'mutation(\$id:String!){podStop(input:{podId:\$id}){id desiredStatus}}' "{\"id\":\"$RUNPOD_POD_ID\"}"
        echo "✅ Pod stopped (cost = \$0)"
        ;;

    destroy)
        if [ -z "${RUNPOD_POD_ID:-}" ]; then echo "Set RUNPOD_POD_ID or source .env.runpod"; exit 1; fi
        gql 'mutation(\$id:String!){podTerminate(input:{podId:\$id})}' "{\"id\":\"$RUNPOD_POD_ID\"}"
        rm -f "$PROJECT_ROOT/.env.runpod"
        echo "✅ Pod destroyed"
        ;;
esac
