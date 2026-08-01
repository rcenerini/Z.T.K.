"""MITRE CAPEC — Common Attack Pattern Enumeration and Classification.

Fonte: https://capec.mitre.org/
Versao: CAPEC v3.9
Mapeamento: CAPEC → CWE → MITRE ATT&CK technique

Usado por: L1.04 Criticality Tagger, L3 PoC Runner, L4 Score Engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CAPECDomain(str, Enum):
    SOFTWARE = "Software"
    HARDWARE = "Hardware"
    COMMUNICATIONS = "Communications"
    SUPPLY_CHAIN = "Supply Chain"
    SOCIAL_ENGINEERING = "Social Engineering"
    PHYSICAL_SECURITY = "Physical Security"


class CAPECLikelihood(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class CAPECPattern:
    """Single CAPEC attack pattern."""
    capec_id: str
    name: str
    domain: CAPECDomain
    likelihood: CAPECLikelihood
    cwe_ids: list[str] = field(default_factory=list)
    att_techniques: list[str] = field(default_factory=list)
    description: str = ""
    severity_impact: str = "P2"
    typical_severity: str = "Medium"


CAPEC_CATALOG: dict[str, CAPECPattern] = {
    # ── Software: Injection Patterns ──
    "CAPEC-66": CAPECPattern(
        capec_id="CAPEC-66", name="SQL Injection",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.HIGH,
        cwe_ids=["CWE-89"],
        att_techniques=["T1190", "T1210"],
        description="Explora SQL queries mal construidas para acessar/modificar dados",
        severity_impact="P0", typical_severity="High",
    ),
    "CAPEC-88": CAPECPattern(
        capec_id="CAPEC-88", name="OS Command Injection",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.HIGH,
        cwe_ids=["CWE-78", "CWE-77"],
        att_techniques=["T1059", "T1190"],
        description="Injeta comandos no sistema operacional via parametros nao sanitizados",
        severity_impact="P0", typical_severity="Critical",
    ),
    "CAPEC-63": CAPECPattern(
        capec_id="CAPEC-63", name="Cross-Site Scripting (XSS)",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.HIGH,
        cwe_ids=["CWE-79", "CWE-80"],
        att_techniques=["T1190", "T1189"],
        description="Injeta HTML/JavaScript em paginas web visualizadas por outros usuarios",
        severity_impact="P1", typical_severity="Medium",
    ),
    "CAPEC-586": CAPECPattern(
        capec_id="CAPEC-586", name="Object Injection / Insecure Deserialization",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-502"],
        att_techniques=["T1190", "T1210"],
        description="Explora desserializacao de objetos para execucao remota de codigo",
        severity_impact="P0", typical_severity="Critical",
    ),
    "CAPEC-664": CAPECPattern(
        capec_id="CAPEC-664", name="Server-Side Request Forgery (SSRF)",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-918"],
        att_techniques=["T1190", "T1071"],
        description="Forca o servidor a fazer requisicoes para destinos controlados pelo atacante",
        severity_impact="P1", typical_severity="High",
    ),

    # ── Software: Authentication/Authorization ──
    "CAPEC-114": CAPECPattern(
        capec_id="CAPEC-114", name="Authentication Abuse/ByPass",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.HIGH,
        cwe_ids=["CWE-287", "CWE-306", "CWE-307"],
        att_techniques=["T1021", "T1552"],
        description="Bypass ou abuso de mecanismos de autenticacao",
        severity_impact="P0", typical_severity="Critical",
    ),
    "CAPEC-115": CAPECPattern(
        capec_id="CAPEC-115", name="Authentication Bypass via Spoofing",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-290", "CWE-287"],
        att_techniques=["T1552"],
        description="Spoofing de identidade para bypass de autenticacao (ex: IP spoofing)",
        severity_impact="P1", typical_severity="High",
    ),
    "CAPEC-1": CAPECPattern(
        capec_id="CAPEC-1", name="Accessing Functionality Not Properly Constrained by ACLs",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-276", "CWE-732", "CWE-862"],
        att_techniques=["T1068", "T1548"],
        description="Acessa funcionalidades sem verificacao adequada de permissao",
        severity_impact="P1", typical_severity="High",
    ),

    # ── Software: Cryptographic ──
    "CAPEC-608": CAPECPattern(
        capec_id="CAPEC-608", name="Cryptanalytic Attack via Weak Algorithm",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-327", "CWE-328", "CWE-329"],
        att_techniques=["T1573", "T1552"],
        description="Explora algoritmos criptograficos fracos (MD5, SHA-1, DES, RC4)",
        severity_impact="P1", typical_severity="Medium",
    ),
    "CAPEC-20": CAPECPattern(
        capec_id="CAPEC-20", name="Encryption Brute Forcing",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.LOW,
        cwe_ids=["CWE-327", "CWE-326"],
        att_techniques=["T1110"],
        description="Forca bruta contra chaves de criptografia fracas ou mal implementadas",
        severity_impact="P2", typical_severity="Medium",
    ),

    # ── Software: Data Exposure ──
    "CAPEC-116": CAPECPattern(
        capec_id="CAPEC-116", name="Excavation of Sensitive Data",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-200", "CWE-201", "CWE-532", "CWE-538"],
        att_techniques=["T1005", "T1048"],
        description="Extracao de dados sensiveis via logs, mensagens de erro, ou metadata",
        severity_impact="P1", typical_severity="Medium",
    ),
    "CAPEC-126": CAPECPattern(
        capec_id="CAPEC-126", name="Path Traversal",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.HIGH,
        cwe_ids=["CWE-22", "CWE-23", "CWE-35"],
        att_techniques=["T1005"],
        description="Acessa arquivos fora do diretorio pretendido via ../ sequences",
        severity_impact="P1", typical_severity="High",
    ),
    "CAPEC-23": CAPECPattern(
        capec_id="CAPEC-23", name="File Content Injection",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-434"],
        att_techniques=["T1190"],
        description="Upload de arquivo malicioso sem validacao de tipo/extensao",
        severity_impact="P1", typical_severity="High",
    ),

    # ── Software: Resource Manipulation ──
    "CAPEC-469": CAPECPattern(
        capec_id="CAPEC-469", name="HTTP DoS",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.HIGH,
        cwe_ids=["CWE-400", "CWE-770"],
        att_techniques=["T1499"],
        description="Negacao de servico via consumo excessivo de recursos HTTP",
        severity_impact="P1", typical_severity="Medium",
    ),
    "CAPEC-26": CAPECPattern(
        capec_id="CAPEC-26", name="Leveraging Race Conditions",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.LOW,
        cwe_ids=["CWE-362", "CWE-367"],
        att_techniques=["T1068"],
        description="Explora condicoes de corrida (TOCTOU) para bypass de controles",
        severity_impact="P0", typical_severity="Critical",
    ),

    # ── Software: Memory ──
    "CAPEC-10": CAPECPattern(
        capec_id="CAPEC-10", name="Buffer Overflow via Environment Variables",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-120", "CWE-787", "CWE-119"],
        att_techniques=["T1203", "T1068"],
        description="Estouro de buffer explorando variaveis de ambiente nao validadas",
        severity_impact="P0", typical_severity="Critical",
    ),
    "CAPEC-14": CAPECPattern(
        capec_id="CAPEC-14", name="Client-side Injection-induced Buffer Overflow",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-416", "CWE-787", "CWE-125"],
        att_techniques=["T1203"],
        description="Use-after-free ou buffer overflow induzido por input do cliente",
        severity_impact="P0", typical_severity="Critical",
    ),

    # ── Software: CSRF / XSRF ──
    "CAPEC-62": CAPECPattern(
        capec_id="CAPEC-62", name="Cross-Site Request Forgery (CSRF)",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.HIGH,
        cwe_ids=["CWE-352"],
        att_techniques=["T1190"],
        description="Forca usuario autenticado a executar acoes nao intencionais",
        severity_impact="P1", typical_severity="High",
    ),

    # ── Software: XML ──
    "CAPEC-201": CAPECPattern(
        capec_id="CAPEC-201", name="XML External Entity (XXE) Attack",
        domain=CAPECDomain.SOFTWARE, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-611"],
        att_techniques=["T1190"],
        description="Explora processamento de entidades externas em XML para ler arquivos",
        severity_impact="P1", typical_severity="High",
    ),

    # ── Supply Chain ──
    "CAPEC-439": CAPECPattern(
        capec_id="CAPEC-439", name="Manipulation During Distribution",
        domain=CAPECDomain.SUPPLY_CHAIN, likelihood=CAPECLikelihood.LOW,
        cwe_ids=["CWE-506", "CWE-494"],
        att_techniques=["T1195", "T1027"],
        description="Insercao de codigo malicioso durante a distribuicao de software",
        severity_impact="P0", typical_severity="Critical",
    ),
    "CAPEC-702": CAPECPattern(
        capec_id="CAPEC-702", name="Supply Chain Compromise via Dependency Confusion",
        domain=CAPECDomain.SUPPLY_CHAIN, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-427", "CWE-506"],
        att_techniques=["T1195"],
        description="Publica pacote malicioso com nome similar a dependencia interna",
        severity_impact="P0", typical_severity="Critical",
    ),

    # ── Social Engineering ──
    "CAPEC-98": CAPECPattern(
        capec_id="CAPEC-98", name="Phishing",
        domain=CAPECDomain.SOCIAL_ENGINEERING, likelihood=CAPECLikelihood.HIGH,
        cwe_ids=["CWE-451"],
        att_techniques=["T1566"],
        description="Engenharia social para obter credenciais via email/site falso",
        severity_impact="P1", typical_severity="Medium",
    ),

    # ── Communications ──
    "CAPEC-94": CAPECPattern(
        capec_id="CAPEC-94", name="Adversary in the Middle (AITM)",
        domain=CAPECDomain.COMMUNICATIONS, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-300", "CWE-319"],
        att_techniques=["T1557", "T1573"],
        description="Intercepta comunicacao entre cliente e servidor",
        severity_impact="P1", typical_severity="High",
    ),
    "CAPEC-117": CAPECPattern(
        capec_id="CAPEC-117", name="Interception of Sensitive Information",
        domain=CAPECDomain.COMMUNICATIONS, likelihood=CAPECLikelihood.MEDIUM,
        cwe_ids=["CWE-319", "CWE-311", "CWE-200"],
        att_techniques=["T1040", "T1557"],
        description="Intercepta dados sensiveis em transito (sniffing, MITM)",
        severity_impact="P1", typical_severity="High",
    ),
}


# ── Query Functions ───────────────────────────────────────────────

def get_patterns_for_cwe(cwe_id: str) -> list[CAPECPattern]:
    """Return all CAPEC attack patterns mapped to a CWE."""
    return [p for p in CAPEC_CATALOG.values() if cwe_id in p.cwe_ids]

def get_patterns_by_domain(domain: CAPECDomain) -> list[CAPECPattern]:
    """Return all patterns for a domain."""
    return [p for p in CAPEC_CATALOG.values() if p.domain == domain]

def get_critical_patterns() -> list[CAPECPattern]:
    """Return P0 patterns."""
    return [p for p in CAPEC_CATALOG.values() if p.severity_impact == "P0"]

def get_capec_severity_boost(cwe_ids: list[str]) -> float:
    """Calculate severity boost based on CAPEC coverage."""
    boost = 0.0
    for cwe_id in cwe_ids:
        for pattern in get_patterns_for_cwe(cwe_id):
            if pattern.severity_impact == "P0":
                boost += 0.5
            elif pattern.severity_impact == "P1":
                boost += 0.25
    return min(3.0, boost)
