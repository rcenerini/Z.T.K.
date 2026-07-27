"""MITRE ATLAS — Adversarial Threat Landscape for AI Systems.

Fonte: https://atlas.mitre.org/
Versao: ATLAS v5.0
Foco: Ameacas especificas a sistemas LLM e ML.

Usado por: L1.03 Prompt Guard, L7 Model Router, L8 Shadow Mode.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ATLASTactic(str, Enum):
    RECON = "Reconnaissance"
    RESOURCE_DEV = "Resource Development"
    ML_ATTACK_STAGING = "ML Attack Staging"
    INITIAL_ACCESS = "Initial Access"
    ML_MODEL_ACCESS = "ML Model Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    DEFENSE_EVASION = "Defense Evasion"
    DISCOVERY = "Discovery"
    COLLECTION = "Collection"
    ML_ATTACK_EXECUTION = "ML Attack Execution"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


@dataclass
class ATLASTechnique:
    technique_id: str
    name: str
    tactic: ATLASTactic
    description: str
    ztk_mitigation: str = ""  # How Z.T.K. mitigates this
    severity: str = "P1"
    owasp_llm_id: str = ""  # OWASP Top 10 for LLM mapping


ATLAS_CATALOG: dict[str, ATLASTechnique] = {
    # ── ML Attack Staging ──
    "AML.T0000": ATLASTechnique(
        technique_id="AML.T0000", name="Create Proxy Model",
        tactic=ATLASTactic.ML_ATTACK_STAGING,
        description="Atacante cria modelo proxy para testar ataques antes de atingir o modelo alvo",
        ztk_mitigation="L8 Shadow Mode: 30 dias de validacao antes de promover modelo",
        severity="P1",
    ),
    "AML.T0001": ATLASTechnique(
        technique_id="AML.T0001", name="Acquire Public ML Artifacts",
        tactic=ATLASTactic.ML_ATTACK_STAGING,
        description="Coleta de datasets publicos, modelos open-source para engenharia reversa",
        ztk_mitigation="Modelos locais (vLLM) nao expostos externamente",
        severity="P2",
    ),

    # ── Initial Access ──
    "AML.T0017": ATLASTechnique(
        technique_id="AML.T0017", name="ML Supply Chain Compromise",
        tactic=ATLASTactic.INITIAL_ACCESS,
        description="Comprometimento de modelos ou datasets na cadeia de fornecimento",
        ztk_mitigation="L8 Tool Lifecycle: monitoramento de updates com checksum",
        severity="P0",
        owasp_llm_id="LLM05",
    ),
    "AML.T0018": ATLASTechnique(
        technique_id="AML.T0018", name="ML Artifact Poisoning",
        tactic=ATLASTactic.INITIAL_ACCESS,
        description="Injecao de dados maliciosos no dataset de treinamento",
        ztk_mitigation="L1.03 Prompt Guard: bloqueia injecao de dados",
        severity="P0",
        owasp_llm_id="LLM03",
    ),

    # ── ML Model Access ──
    "AML.T0040": ATLASTechnique(
        technique_id="AML.T0040", name="ML Model Inference API Access",
        tactic=ATLASTactic.ML_MODEL_ACCESS,
        description="Acesso nao autorizado a API de inferencia do modelo",
        ztk_mitigation="L7 Model Router: apenas via vLLM local (PCI) ou Bedrock com IAM",
        severity="P0",
    ),
    "AML.T0024": ATLASTechnique(
        technique_id="AML.T0024", name="Exfiltrate ML Model",
        tactic=ATLASTactic.EXFILTRATION,
        description="Extracao do modelo treinado (model weights, arquitetura)",
        ztk_mitigation="vLLM local sem acesso a rede externa; sem storage persistente",
        severity="P0",
    ),

    # ── ML Attack Execution ──
    "AML.T0015": ATLASTechnique(
        technique_id="AML.T0015", name="Evade ML Model",
        tactic=ATLASTactic.ML_ATTACK_EXECUTION,
        description="Amostras adversariais que enganam o modelo (perturbacao minima)",
        ztk_mitigation="L7 Circuit Breaker: detecta anomalias e pausa tier caro",
        severity="P0",
    ),
    "AML.T0051": ATLASTechnique(
        technique_id="AML.T0051", name="Prompt Injection",
        tactic=ATLASTactic.ML_ATTACK_EXECUTION,
        description="Injecao de instrucoes maliciosas no prompt do LLM",
        ztk_mitigation="L1.03 Prompt Guard: regex + envelopamento (ADR-003)",
        severity="P0",
        owasp_llm_id="LLM01",
    ),
    "AML.T0054": ATLASTechnique(
        technique_id="AML.T0054", name="Jailbreak",
        tactic=ATLASTactic.ML_ATTACK_EXECUTION,
        description="Bypass de restricoes de seguranca do LLM (DAN, roleplay)",
        ztk_mitigation="L1.03 Prompt Guard: deteccao de jailbreak patterns",
        severity="P0",
        owasp_llm_id="LLM01",
    ),
    "AML.T0057": ATLASTechnique(
        technique_id="AML.T0057", name="LLM Data Leakage",
        tactic=ATLASTactic.EXFILTRATION,
        description="Extracao de dados de treinamento via prompts crafted",
        ztk_mitigation="L7 Data Sovereignty: PCI/PII nunca tocam Bedrock",
        severity="P0",
        owasp_llm_id="LLM06",
    ),
    "AML.T0029": ATLASTechnique(
        technique_id="AML.T0029", name="Extract Training Data",
        tactic=ATLASTactic.EXFILTRATION,
        description="Ataque de inversao de modelo para recuperar dados de treinamento",
        ztk_mitigation="L8 Multi-tenancy: isolamento de dados por tenant",
        severity="P0",
    ),
    "AML.T0048": ATLASTechnique(
        technique_id="AML.T0048", name="LLM Hallucination Exploit",
        tactic=ATLASTactic.ML_ATTACK_EXECUTION,
        description="Exploracao de alucinacoes para gerar codigo inseguro ou decisoes erradas",
        ztk_mitigation="L4 Debate Engine: consenso adversarial detecta divergencia",
        severity="P1",
        owasp_llm_id="LLM08",
    ),
    "AML.T0030": ATLASTechnique(
        technique_id="AML.T0030", name="Backdoor ML Model",
        tactic=ATLASTactic.PERSISTENCE,
        description="Insercao de backdoor no modelo que ativa com trigger especifico",
        ztk_mitigation="L8 Shadow Mode: validacao continua de 30 dias",
        severity="P0",
        owasp_llm_id="LLM05",
    ),
    "AML.T0047": ATLASTechnique(
        technique_id="AML.T0047", name="Craft Adversarial Data",
        tactic=ATLASTactic.ML_ATTACK_STAGING,
        description="Criacao de dados especificos para enganar o modelo alvo",
        ztk_mitigation="L1.03 Unicode normalisation + homoglyph detection",
        severity="P1",
    ),
    "AML.T0056": ATLASTechnique(
        technique_id="AML.T0056", name="LLM Plugin Compromise",
        tactic=ATLASTactic.EXECUTION,
        description="Comprometimento de plugins/tools do LLM para execucao de codigo",
        ztk_mitigation="L7 Data Sovereignty: circuit breaker de custo e escopo",
        severity="P0",
        owasp_llm_id="LLM07",
    ),
    "AML.T0053": ATLASTechnique(
        technique_id="AML.T0053", name="Insecure Output Handling",
        tactic=ATLASTactic.ML_ATTACK_EXECUTION,
        description="LLM gera output malicioso (XSS, SQLi) que e executado downstream",
        ztk_mitigation="L3 Sandbox: validacao de patch em ambiente isolado",
        severity="P0",
        owasp_llm_id="LLM02",
    ),
}


# ── Query Functions ───────────────────────────────────────────────

def get_atlas_mitigations() -> dict[str, str]:
    """Return mitigation summary for each ATLAS threat."""
    return {t.technique_id: t.ztk_mitigation for t in ATLAS_CATALOG.values()}

def get_p0_atlas_threats() -> list[ATLASTechnique]:
    """Return P0 (critical) ATLAS threats."""
    return [t for t in ATLAS_CATALOG.values() if t.severity == "P0"]
