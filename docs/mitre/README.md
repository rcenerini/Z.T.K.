# MITRE Catalogs — Z.T.K. Threat Intelligence

![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK_Enterprise-ff6b35)
![ATLAS](https://img.shields.io/badge/MITRE-ATLAS_v5-7b42bc)
![Techniques](https://img.shields.io/badge/techniques-43-00d4ff)
![CWEs](https://img.shields.io/badge/CWEs_mapped-38-00ff88)

> **Versao:** 1.0 | **Fonte:** MITRE Corporation | **Modulo:** `src/shared/catalog/`

---

## 1. Visao Geral

O Z.T.K. integra os frameworks MITRE para enriquecer a analise de vulnerabilidades:

| Catalogo | Tecnicas | CWEs Mapeados | Foco |
|----------|----------|--------------|------|
| **ATT&CK Enterprise** | 28 | 38 | Tecnicas de ataque a sistemas enterprise |
| **ATLAS** | 15 | — | Ameacas especificas a LLM/ML |
| **CAPEC** | Futuro | — | Attack patterns (em breve) |

---

## 2. MITRE ATT&CK Enterprise

28 tecnicas mapeadas para 38 CWEs em 12 das 14 taticas ATT&CK.

### Por Tatica

| Tatica | Tecnicas | Exemplos |
|--------|----------|----------|
| Initial Access | 3 | T1190 (Exploit Public-Facing), T1189 (Drive-by) |
| Execution | 3 | T1059 (Cmd Interpreter), T1203 (Client Exec) |
| Privilege Escalation | 2 | T1068 (Exploit for PrivEsc), T1548 (Abuse Elevation) |
| Credential Access | 4 | T1003 (Cred Dump), T1552 (Unsecured Creds) |
| Defense Evasion | 3 | T1027 (Obfuscation), T1562 (Impair Defenses) |
| Lateral Movement | 2 | T1210 (Remote Exploit), T1021 (Remote Services) |
| Exfiltration | 1 | T1048 (Alt Protocol) |
| Impact | 2 | T1485 (Data Destruction), T1499 (DoS) |

### Integracao com SAST Agents

| CWE | ATT&CK Technique | SAST Agents | Severidade |
|-----|-----------------|-------------|-----------|
| CWE-89 | T1190, T1210 | Bandit, Semgrep | P0 |
| CWE-78 | T1190, T1059, T1210 | Bandit, Semgrep | P0 |
| CWE-79 | T1190, T1189, T1566 | Bandit, Semgrep, ESLint | P1 |
| CWE-798 | T1003, T1552, T1555 | Gitleaks, TruffleHog | P0 |
| CWE-502 | T1190, T1210 | Bandit, Semgrep | P0 |
| CWE-918 | T1190, T1071 | Bandit, Semgrep | P1 |
| CWE-327 | T1573 | Bandit, Semgrep | P1 |
| CWE-416 | T1203, T1068, T1210 | Cppcheck, CodeQL-CPP | P0 |
| CWE-416, CWE-787 | T1203 | Cppcheck, CodeQL-CPP | P0 |

---

## 3. MITRE ATLAS (LLM/ML Threats)

15 tecnicas focadas em sistemas LLM/ML, com mitigacoes especificas do Z.T.K.

### Por Severidade

| Severidade | Quantidade | Tecnicas |
|-----------|-----------|----------|
| **P0** | 12 | Supply chain, poisoning, prompt injection, jailbreak, data leakage, model exfil |
| **P1** | 3 | Proxy model, adversarial data, hallucination exploit |

### Mapeamento OWASP LLM Top 10

| ATLAS | OWASP LLM | Descricao | Mitigacao ZTK |
|-------|-----------|-----------|--------------|
| AML.T0051 | LLM01 | Prompt Injection | L1.03 Prompt Guard |
| AML.T0054 | LLM01 | Jailbreak | L1.03 Jailbreak patterns |
| AML.T0053 | LLM02 | Insecure Output | L3 Sandbox validation |
| AML.T0018 | LLM03 | Training Data Poisoning | L1.03 Prompt Guard |
| AML.T0017 | LLM05 | Supply Chain | L8 Tool Lifecycle |
| AML.T0057 | LLM06 | Sensitive Info Disclosure | L7 Data Sovereignty |
| AML.T0056 | LLM07 | Insecure Plugin Design | L7 Circuit Breaker |
| AML.T0048 | LLM08 | Excessive Agency | L4 Debate Engine |

---

## 4. Uso no Pipeline

### L1.04 — Criticality Tagger

```python
from shared.catalog.mitre_attack import get_severity_boost

# Aumenta score baseado no mapeamento ATT&CK
boost = get_severity_boost(finding.cwe_ids)
criteria_score = base_score + boost
```

### L2 — SAST Agent Selection

```python
from shared.catalog.mitre_attack import get_techniques_for_cwe

# Determinar quais SAST agents detectam este CWE
techniques = get_techniques_for_cwe("CWE-89")
agents = [a for t in techniques for a in t.sa_agents]
```

---

## 5. Expansao

Para adicionar novas tecnicas:

1. Adicione entrada em `ATTACK_CATALOG` ou `ATLAS_CATALOG`
2. Mapeie CWEs relevantes
3. Especifique severidade (P0-P4)
4. Liste SAST agents que detectam essa tecnica
5. Adicione teste em `test_mitre.py`
