# CLAUDE.md — Contexto Persistente do Projeto Z.T.K.

> **Versao:** 1.0 | **Projeto:** Z.T.K. (Zero Trust Kill) | **Stack:** AWS
>
> Este arquivo eh o contrato de contexto para todos os agentes de IA trabalhando
> neste repositorio. Leia antes de qualquer implementacao.

## 1. Princípios Invioláveis

1. **LLM nunca eh decisor primario de seguranca** — so interpreta saida de ferramenta
2. **Fail-closed:** dado ausente = comportamento conservador, nunca otimista
3. **Toda decisao gera audit event correlacionavel por `finding_id`**
4. **Nenhuma credencial hardcoded** — sempre AWS Secrets Manager + IAM least privilege
5. **Lambda/Container que nao precisa de VPC fica fora da VPC**
6. **Motor de decisao eh funcao pura** — sem chamada externa direta
7. **Orquestracao multi-step vive em Step Functions**, nunca em codigo
8. **Runbooks sao configuracao declarativa (YAML)**, nao codigo imperativo
9. **Idempotencia em tudo que grava estado externo**
10. **Shadow mode eh cidadao de primeira classe desde v1**
11. **Dados PCI/CHD/PAN nunca tocam Bedrock** — vLLM local obrigatorio
12. **Nenhum merge automatico em P0/P1** — aprovacao humana obrigatoria

## 2. Stack Técnica AWS

| Camada | Tecnologia | Justificativa de Custo |
|---|---|---|
| **Runtime Agentes Leves** | AWS Lambda (Python 3.12) | Serverless, paga-so-pelo-uso, ideal para conectores e triagem |
| **Runtime Agentes Medios** | ECS Fargate (spot) | Mais barato que EKS para tarefas efemeras; sem gerenciar nodes |
| **Runtime Agentes Pesados (GPU)** | EC2 g5.xlarge Spot + vLLM | Custo minimo para inferencia local; spot reduz ~70% |
| **LLM Pago** | AWS Bedrock (Claude Sonnet/Haiku) | Paga por token, elastico, sem infra; **NAO para PCI** |
| **Orquestracao** | AWS Step Functions | Serverless, visual, auditavel nativamente |
| **Fila/Mensageria** | SQS (DLQ por fonte) + EventBridge | Isolamento por conector, retry com backoff |
| **Banco de Dados** | DynamoDB (serverless) + S3 (data lake) | Sem provisionamento, auto-scaling, replicacao multi-AZ |
| **Dashboard** | Grafana Enterprise (ECS Fargate) + Athena/QuickSight | Grafana para operadores; Athena para queries ad-hoc |
| **Infraestrutura** | Terraform (IaC) | Golden modules, drift detection, versionado |
| **Policy Engine** | OPA/Rego | Deny-by-default, testavel, versionado em Git |
| **Observabilidade** | CloudWatch + X-Ray + Grafana | Metricas, traces, logs estruturados |
| **Segredos** | AWS Secrets Manager + Parameter Store | Rotacao automatica, IAM restrito |

## 3. Estrutura de Diretórios

```
/
├── .github/                    # Templates PR, issues, workflows CI/CD
├── .opencode/                  # Configuracao dos agentes OpenCode
├── docs/
│   ├── architecture/           # ADRs, diagramas, threat models
│   ├── ssdld/                # Artefatos S-SDLC (requirements, design, tests)
│   └── runbooks/             # Runbooks de mitigacao declarativos (YAML)
├── infra/
│   ├── terraform/              # Modulos golden AWS
│   ├── policies/             # OPA/Rego policies
│   └── grafana/              # Dashboards e datasources
├── src/
│   ├── layer1_ingress/       # Camada 1: Entrada & Triagem
│   ├── layer2_specialists/     # Camada 2: Especialistas de Seguranca
│   ├── layer3_validation/      # Camada 3: Reachability, PoC, Fuzzing
│   ├── layer4_consensus/       # Camada 4: Debate Adversarial
│   ├── layer5_remediation/     # Camada 5: Patch + Contencao
│   ├── layer6_governance/      # Camada 6: Policy Engine, Auditoria, HITL
│   ├── layer7_model_ensemble/  # Camada 7: Roteamento LLM, vLLM, Bedrock
│   ├── layer8_scale/           # Camada 8: Ativacao, Onboarding, Multi-tenant
│   └── shared/                 # Schemas, utils, observabilidade
├── tests/
│   ├── unit/                   # Testes unitarios por camada
│   ├── integration/            # Testes de integracao
│   ├── contract/               # Contract tests para APIs externas
│   ├── security/               # SAST, DAST, fuzzing local
│   └── e2e/                    # Testes end-to-end (Step Functions)
├── scripts/
│   ├── pre-commit/             # Hooks de seguranca
│   ├── quality-gates/          # Scripts de quality gates CI
│   └── deploy/                 # Scripts de deploy seguro
├── interface_excecoes/         # Interface web para tratamento de excecoes
│   ├── backend/                # API Gateway + Lambda (Python)
│   └── frontend/               # React/Next.js (statico em S3+CloudFront)
└── CLAUDE.md                   # Este arquivo
```

## 4. Convenções de Código

- **Python 3.12+** com type hints obrigatorios (`mypy --strict`)
- **Pydantic v2** para todos os schemas de entrada/saida
- **pytest** com fixtures parametrizadas
- **Estrutura por Lambda/Container:** `handler.py` → `service.py` → `repository.py`
- **Async/await** para chamadas IO-bound
- **Context managers** para recursos (boto3 sessions, connections)
- **Nunca `print`** — usar structlog/json logging
- **Nunca exceptions nao tratadas** — sempre `try/except` com fallback fail-closed

## 5. Roteamento de Modelos LLM (Camada 7)

| Cenario | Modelo | Justificativa |
|---|---|---|
| Dados PCI/CHD/PAN | vLLM local (EC2 g5 + Llama 3.3/Qwen 2.5) | Dados nunca saem da VPC |
| Debate, consenso, reasoning | DeepSeek R1 via API | Custo baixo, chain-of-thought |
| Codigo >1000 linhas, diffs grandes | Kimi k2.6 | Contexto longo (200k tokens) |
| Arquitetura, ADRs, scoring com pesos | Claude Opus 4 via Bedrock | Uso cirurgico, aprovacao humana |
| Desenvolvimento, patch, IaC | Claude Sonnet 5 via Bedrock | Workhorse tecnico |
| Triagem, classificacao, logs | Claude Haiku 4.5 via Bedrock | Custo minimo, volume alto |
| Geracao em massa de agentes | Claude Batch API | Economia de 50% em volume |

## 6. Seguranca dos Agentes (Agentic Security)

- **SPIFFE/SPIRE** para identidade de workload (opcional na v1; JWT curto na v1)
- **Cada agente** com role IAM dedicada (least privilege)
- **Credenciais de deploy (Camada 5)** com max_depth=0 — nunca propagam
- **Sandbox:** containers com `readOnlyRootFilesystem`, `runAsNonRoot`, seccomp
- **Recursive Guard:** max_depth=3, max_total_calls=20, budget_tokens=100k
- **Memory Poisoning Protection:** conteudo de ferramentas = untrusted default
- **HITL Gates:** `new_agent_deployment`, `tool_permission_change`, `merge_guardrail`, `deploy_production`, `exception_four_eyes`

## 7. S-SDLC / DevSecOps

| Fase | Gates Obrigatorios |
|---|---|
| **Requirements** | EARS, ASVS, security user stories, threat model STRIDE |
| **Design** | ADR aprovado, matriz de testes definida, contratos de API |
| **Code** | SAST (Semgrep/Bandit), SCA (Snyk), secrets (TruffleHog), SBOM |
| **Build** | Signed builds, reproducible builds, container scan (Trivy) |
| **Test** | Unit (pytest), integration, contract, fuzzing, fail-closed |
| **Deploy** | OPA/Rego admission, image signing (Cosign), IaC scan (Checkov) |
| **Operate** | Grafana dashboards, CloudWatch alerts, HITL queue, kill switch test |

## 8. Interface de Excecoes

- **Backend:** API Gateway + Lambda Python (JWT auth, rate limiting)
- **Frontend:** React/Next.js estatico em S3 + CloudFront
- **Funcionalidades:**
  - Fila de excecoes pendentes (four-eyes)
  - Aprovacao/rejeicao com justificativa obrigatoria
  - Timeline de auditoria por `finding_id`
  - Dashboard de SLA estourado
  - Kill switch de emergencia (autoridade SOC)

## 9. Grafana Enterprise Dashboards

- **Painel de Operacao:** findings por severidade, tempo de resposta, fila HITL
- **Painel de Seguranca:** agentes ativos, falhas de sandbox, tentativas de prompt injection
- **Painel de Custo:** consumo Bedrock, GPU-hours, tokens por camada
- **Painel de Compliance:** SLA PCI, renovacoes de TTL, excecoes pendentes
- **Datasource:** CloudWatch + Athena (S3) + Prometheus (ECS/EKS)

## 10. Decisoes Pendentes (Aguardam Intervencao Humana)

| ID | Decisao | Stakeholder |
|---|---|---|
| D001 | EKS vs ECS Fargate para agentes de longa duracao | Arquiteto + PO |
| D002 | Modelo local PCI: Llama 3.3 70B vs Qwen 2.5 72B | Engenheiro IA + CISO |
| D003 | Grafana Enterprise: self-hosted ECS ou Amazon Managed Grafana? | Plataforma + Custo |
| D004 | Interface de excecoes: Next.js vs Vue vs Angular? | UX + Engenheiro |
| D005 | Bedrock Claude vs DeepSeek API para debate (nao-PCI)? | Engenheiro IA + Custo |
| D006 | On-premise connector: VPN Direct Connect ou VPC peering? | Cloud Architect |

---

*Ultima atualizacao: 2026-07-25*
*Agentes devem validar este documento a cada sprint*
