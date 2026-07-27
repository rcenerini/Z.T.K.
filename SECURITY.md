# Política de Segurança

## Reportando Vulnerabilidades

Se você encontrar uma vulnerabilidade de segurança no Z.T.K., **NÃO** abra uma issue pública.

Envie um email para o maintainer com:
- Descrição da vulnerabilidade
- Passos para reproduzir
- Impacto potencial
- Sugestão de correção (se tiver)

## Escopo

O escopo de segurança inclui:
- Código fonte (`src/`, `mvp2/`)
- Infraestrutura como código (`infra/`)
- Pipelines CI/CD (`.github/workflows/`)
- Dependências (`pyproject.toml`)

## Práticas de Segurança

Este projeto segue:
- **PCI DSS 4.0** — proteção de dados sensíveis
- **OWASP Top 10** — prevenção de vulnerabilidades comuns
- **NIST SP 800-53** — controles de segurança
- **CIS Benchmarks** — hardening de infraestrutura

## Versões Suportadas

| Versão | Suporte |
|--------|---------|
| 1.0.x (main) | ✅ Ativo |

## Processo de Divulgação

1. Vulnerabilidade reportada → confirmada em até 72h
2. Correção desenvolvida em branch privada
3. Release com patch de segurança
4. Divulgação pública após 30 dias
