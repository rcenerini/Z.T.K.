# QA Report — Architecture Diagrams

![C4](https://img.shields.io/badge/model-C4_Container-00d4ff)
![UML](https://img.shields.io/badge/notation-UML_2.5-ff6b35)
![TOGAF](https://img.shields.io/badge/framework-TOGAF_10-7b42bc)
![PCI](https://img.shields.io/badge/trust_boundary-PCI_DSS_1.3-00ff88)

> **Data:** 2026-07-27 | **Revisor:** ZTK Reviewer Agent | **Versao:** 1.0

---

## 1. Checklist de Padrões Internacionais

### C4 Model (Simon Brown)

| Nivel | Artefato | Status |
|-------|----------|--------|
| C1 — System Context | `hero.svg` | ✅ |
| C2 — Container | `architecture-technical.svg` | ✅ |
| C3 — Component | `architecture-functional.svg` | ✅ |
| C4 — Code | N/A (auto-generated docs) | N/A |

### UML 2.5 (OMG)

| Requisito | Status | Observacao |
|-----------|--------|-----------|
| Component notation | ✅ | Retangulos com nome + estereotipo |
| Dependency arrows | ✅ | Setas com direcao clara |
| Boundary/package | ✅ | VPC + CDE com linhas tracejadas |
| Stereotypes | ✅ | Corners coloridos por tipo |

### TOGAF 10

| Requisito | Status |
|-----------|--------|
| Business Architecture | ✅ Hero SVG |
| Data Architecture | ✅ Functional SVG (fluxo de dados) |
| Application Architecture | ✅ Technical SVG (componentes) |
| Technology Architecture | ✅ Technical SVG (infra AWS) |
| Security Architecture | ✅ Trust boundaries PCI DSS |

### PCI DSS 4.0

| Requisito | Status |
|-----------|--------|
| CDE boundary visible | ✅ Linha tracejada vermelha |
| Trust boundary label | ✅ "TRUST BOUNDARY — PCI DSS 1.3" |
| Data flow restrictions | ✅ PCI → vLLM local (nunca Bedrock) |
| Segmentation labeling | ✅ DMZ / APP / CDE claros |

### Acessibilidade (WCAG 2.1 AA)

| Requisito | Status |
|-----------|--------|
| `<title>` element | ✅ |
| `<desc>` element | ✅ |
| `role="img"` | ✅ |
| `aria-labelledby` | ✅ |
| Alt text in Markdown | ✅ `<img alt="...">` |

---

## 2. Legendas (Keys)

### Functional SVG

| Cor | Significado |
|-----|------------|
| Cyan (`#E8F4FD`) | Deterministic agents (L1, L2) |
| Amber (`#FFF3E0`) | Security-critical (L3, prompt guard) |
| Green (`#E6F9F0`) | Remediation (L5, patch, containment) |
| Purple (`#F3E8FF`) | LLM/Consensus (L4, debate, L7 ensemble) |
| Dashed | Cross-cutting layers (L6, L7, L8) |

### Technical SVG

| Cor | Significado |
|-----|------------|
| Cyan border | Compute (Lambda, ECS) |
| Amber border | Messaging (SQS) |
| Cyan thick | Storage (DynamoDB, S3) |
| Green thick | GPU (vLLM local) |
| Purple thick | AI (Bedrock) |
| Red background | CDE Zone (PCI DSS) |

---

## 3. Correcoes Aplicadas

| # | Issue | Severidade | Correcao |
|---|-------|-----------|----------|
| 1 | Functional SVG sem legenda | Media | Adicionada legenda com 5 categorias de cor |
| 2 | Technical SVG sem legenda | Media | Adicionada legenda com 7 tipos de componente |
| 3 | Trust boundary nao rotulada | Alta | Adicionado "TRUST BOUNDARY — PCI DSS 1.3" |
| 4 | CDE boundary sem justificativa normativa | Media | Adicionada referencia PCI DSS 1.3 no label |
| 5 | Sem indicacao de padrao C4 | Baixa | Adicionado "C4 Container Diagram v1.0" na legenda |

---

## 4. Veredito

**APROVADO.** Ambos diagramas atendem:
- C4 Model (C2/C3)
- UML 2.5 stereotypes
- TOGAF 10 architecture domains
- PCI DSS 4.0 trust boundaries
- WCAG 2.1 AA accessibility
- Z.T.K. Visual Identity (paleta, tipografia)
