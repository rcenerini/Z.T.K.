# Identidade Visual — Z.T.K. (Zero Trust Kill)

> **Versão:** 1.0 | **Propósito:** Guia de design para todos os assets visuais do projeto

---

## 1. Filosofia Visual

Z.T.K. é um sistema de segurança determinístico. A identidade visual reflete:

- **Precisão** — tipografia mono para dados técnicos
- **Controle** — paleta escura com acentos cromáticos mínimos
- **Camadas** — a arquitetura de 8 camadas aparece como motivo visual recorrente
- **Prova real** — diagramas e schemas são o material nativo do projeto, não decoração

**Regra:** nunca adicionar elementos visuais que não representem algo real do projeto.

---

## 2. Paleta de Cores

| Nome | Hex | Uso |
|------|-----|-----|
| **Background** | `#080c12` | Fundo principal (hero, diagramas) |
| **Panel** | `#1a2332` | Cards, módulos, áreas de conteúdo |
| **Border** | `#2a3a4a` | Bordas sutis entre elementos |
| **Cyan (Precision)** | `#00d4ff` | Ações determinísticas, pipeline, dados |
| **Amber (Threat)** | `#ff6b35` | Ameaças, vulnerabilidades, severidade alta |
| **Green (Safe)** | `#00ff88` | Remediação, conformidade, status OK |
| **Text Primary** | `#e6edf3` | Texto principal |
| **Text Muted** | `#8b949e` | Metadados, labels secundários |

### Regras de uso

- **Cyan** = camadas determinísticas (L1, L2, L6, L7, L8), dados, schemas
- **Amber** = camadas de risco (L3, L4), severidade P0/P1, alerts
- **Green** = remediação (L5), status resolved, compliance OK
- Nunca usar mais de 2 acentos na mesma composição sem justificativa

---

## 3. Tipografia

| Papel | Stack | Peso |
|-------|-------|------|
| **Título principal** | `-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif` | 800 |
| **Subtítulos** | `-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif` | 600 |
| **Corpo** | `-apple-system, BlinkMacSystemFont, Segoe UI, sans-serif` | 400 |
| **Código / Metadados** | `ui-monospace, SFMono-Regular, Menlo, monospace` | 400 |
| **Labels técnicos** | `ui-monospace, SFMono-Regular, Menlo, monospace` | 400 |

**Regra:** nunca carregar fontes remotas. Usar stacks de sistema.

---

## 4. SVG Canvas Padrão

| Tipo | viewBox | Uso |
|------|---------|-----|
| **Hero** | `1200 × 360` | Banner principal do README |
| **Section Title** | `1200 × 140` | Transição entre seções |
| **Diagrama** | `1200 × 320-760` | Arquitetura, fluxos, DFD |
| **Badge** | `240 × 40` | Status, versão, compliance |

### Skeleton

```svg
<svg xmlns="http://www.w3.org/2000/svg"
     width="1200" height="360" viewBox="0 0 1200 360"
     role="img" aria-labelledby="title desc">
  <title id="title">...</title>
  <desc id="desc">...</desc>
  <rect width="1200" height="360" rx="20" fill="#080c12"/>
  <!-- conteúdo -->
</svg>
```

---

## 5. Motivos Nativos do Projeto

O material visual do Z.T.K. vem do próprio código e arquitetura:

| Motivo | Onde usar | Exemplo |
|--------|----------|---------|
| **8 camadas** | Hero, diagramas de arquitetura | Cards empilhados L1→L8 |
| **Pipeline SSVC** | Diagramas de fluxo | Nós conectados: EXPLOITATION → EXPOSURE → MISSION_IMPACT |
| **Matriz de agentes** | Documentação, seções "Quem faz o quê" | Grid 12×N de agentes |
| **Schemas Pydantic** | Exemplos de código, API docs | Blocos JSON estilizados |
| **Finding lifecycle** | Diagramas de estado | RAW → NORMALIZED → ENRICHED → SCORED → DECIDED → RESOLVED |

---

## 6. Hierarquia de Documentação

```
README.md
  ├── Hero SVG (project-native)
  ├── Badges (tecnologia, status, compliance)
  ├── Arquitetura (Mermaid diagram)
  ├── Tabelas de módulos/comparação
  ├── Quick Start (comandos copiáveis)
  └── Footer (licença, contato)

docs/
  ├── architecture/   → ADRs com tabelas de decisão
  ├── runbooks/       → Procedimentos numerados com YAML
  ├── compliance/     → Matrizes de rastreabilidade
  ├── infra/          → Diagrama de arquitetura de rede
  ├── api/            → Schemas request/response
  └── visual-identity/ → Este documento
```

---

## 7. Badges

Usar badges do shields.io com a paleta do projeto:

```markdown
![Python](https://img.shields.io/badge/Python-3.12%2B-00d4ff?logo=python)
![AWS](https://img.shields.io/badge/AWS-Serverless-ff6b35?logo=amazonaws)
![PCI DSS](https://img.shields.io/badge/PCI_DSS-4.0-00ff88)
![License](https://img.shields.io/badge/license-restricted-8b949e)
```

---

## 8. Checklist de Validação Visual

Antes de publicar qualquer asset:

- [ ] O SVG tem `<title>` e `<desc>` para acessibilidade
- [ ] Texto permanece legível em `900px` de largura renderizada
- [ ] Cores não dependem de tema claro/escuro do GitHub
- [ ] Nenhuma fonte remota é carregada
- [ ] O material visual representa algo real do projeto (não é decoração)
- [ ] Se eu remover o nome do repositório, o visual ainda é identificável?
