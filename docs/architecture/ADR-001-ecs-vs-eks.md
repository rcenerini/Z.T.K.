# ADR-001: Escolha de Runtime para Agentes — ECS Fargate Spot vs EKS

**Status:** Proposto (aguardando decisao humana D001)
**Data:** 2026-07-25
**Autor:** Agente Arquiteto
**Stakeholders:** CTO, Cloud Architect, Security Product Owner

## Contexto

O Z.T.K. possui 133 agentes com perfis de execucao distintos:
- **Agentes leves:** Conectores, triagem, normalizacao (< 15 min, event-driven)
- **Agentes medios:** SAST wrappers, validacao, PoC efemero (minutos a horas)
- **Agentes pesados:** vLLM GPU (horas/dias, workload continuo)

Precisamos decidir a plataforma de orquestracao para os agentes medios (nao-leves, nao-GPU).

## Opcoes Consideradas

### Opcao A: Amazon EKS (Kubernetes)

**Pros:**
- Orquestracao madura, auto-scaling HPA/VPA
- Service mesh (Istio/Linkerd) para mTLS entre agentes
- ECR + Helm para deploy de agentes customizados
- Suporte nativo a GPU (para futura expansao)

**Contras:**
- Custo fixo de ~$72/mes por cluster (control plane) + nodes
- Complexidade operacional alta (K8s expertise necessaria)
- Over-provisioning comum (nodes rodando 24/7 para workloads esporadicos)
- Curva de aprendizado para equipe

**Custo estimado (dev):** $400-800/mes

### Opcao B: Amazon ECS Fargate (Spot)

**Pros:**
- Serverless — paga-so-pelo-uso, sem nodes para gerenciar
- Spot reduz custo em ~70% para workloads tolerantes a interrupcao
- Task definitions simples (JSON/Docker)
- Integracao nativa com EventBridge, SQS, Step Functions
- Menor superficie de ataque (sem SSH, no host access)

**Contras:**
- Sem service mesh nativo (solucionavel via VPC + Security Groups)
- Cold start de ~30s para tarefas (aceitavel para SAST)
- Limite de 4 vCPU / 30GB RAM por tarefa (suficiente para SAST)

**Custo estimado (dev):** $80-200/mes

### Opcao C: Hibrido — Lambda (leves) + ECS Fargate Spot (medios) + EC2 Spot GPU (pesados)

**Pros:**
- Custo otimizado por perfil de workload
- Lambda para eventos rapidos (sem cold start)
- ECS para batch jobs (SAST, PoC)
- EC2 para vLLM (GPU obrigatorio)

**Contras:**
- Tres plataformas para operar
- Complexidade de networking entre elas

**Custo estimado (dev):** $150-400/mes

## Recomendacao do Agente

**Opcao C (Hibrido)** com enfase em **ECS Fargate Spot** para agentes medios.

Justificativa:
1. **Custo:** Spot reduz ~70% vs on-demand; Fargate elimina custo de node ocioso
2. **Seguranca:** Menor superficie (sem host access), read-only root FS facilmente configuravel
3. **Escalabilidade:** EventBridge/SQS disparam tarefas automaticamente; nao precisamos de K8s complexity
4. **PCI:** ECS Fargate eh servico PCI-compliant; podemos isolar tasks por Security Group
5. **Evolucao:** Se precisarmos de service mesh no futuro, migramos para EKS gradualmente (Camada 8)

## Decisao Pendente

**D001:** Aprovamos Opcao C (Hibrido Lambda + ECS Fargate Spot + EC2 Spot GPU)?

Se sim:
- ECS Fargate Spot como padrao para Camada 2/3
- Lambda como padrao para Camada 1/6
- EC2 Spot GPU para Camada 7 (vLLM)

Se nao:
- Reavaliar Opcao A (EKS) com justificativa de custo

## Consequencias

- **Positivas:** Custo 3-5x menor que EKS, operacao simplificada
- **Negativas:** Sem service mesh nativo (mitigado via SG + VPC Flow Logs)
- **Riscos:** Interrupcao de Spot tasks (mitigado via DLQ + retry idempotente)

---

*Este ADR foi gerado pelo agente arquiteto. Aguarda aprovacao humana.*
