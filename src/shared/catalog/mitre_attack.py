"""MITRE ATT&CK Enterprise — Catalogo de tecnicas mapeadas a CWEs.

Fonte: https://attack.mitre.org/
Versao: ATT&CK v16 (2025)
Mapeamento: CWE → MITRE ATT&CK technique → tactic.

Usado por: L1.04 Criticality Tagger, L2 SAST Agents, L4 Score Engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ATTACKTactic(str, Enum):
    """MITRE ATT&CK Enterprise tactics."""
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


@dataclass
class ATTACKTechnique:
    """Single MITRE ATT&CK technique mapped to CWEs."""
    technique_id: str
    name: str
    tactic: ATTACKTactic
    cwe_ids: list[str] = field(default_factory=list)
    description: str = ""
    severity_impact: str = "P2"  # Default impact on severity
    sa_agents: list[str] = field(default_factory=list)  # SAST agents that detect this


# ── ATT&CK ↔ CWE Mapping ──────────────────────────────────────────

ATTACK_CATALOG: dict[str, ATTACKTechnique] = {
    # ── Initial Access ──
    "T1190": ATTACKTechnique(
        technique_id="T1190", name="Exploit Public-Facing Application",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        cwe_ids=["CWE-89", "CWE-78", "CWE-79", "CWE-502", "CWE-918", "CWE-22"],
        description="Explora vulnerabilidades em aplicacoes expostas (SQLi, XSS, RCE)",
        severity_impact="P0",
        sa_agents=["L2.01-bandit", "L2.02-semgrep-python"],
    ),
    "T1189": ATTACKTechnique(
        technique_id="T1189", name="Drive-by Compromise",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        cwe_ids=["CWE-79", "CWE-494"],
        description="Usuario visita website comprometido que explora browser",
        severity_impact="P1",
    ),
    "T1566": ATTACKTechnique(
        technique_id="T1566", name="Phishing",
        tactic=ATTACKTactic.INITIAL_ACCESS,
        cwe_ids=["CWE-79", "CWE-451"],
        description="Email com link/attachment malicioso",
        severity_impact="P1",
    ),

    # ── Execution ──
    "T1059": ATTACKTechnique(
        technique_id="T1059", name="Command and Scripting Interpreter",
        tactic=ATTACKTactic.EXECUTION,
        cwe_ids=["CWE-78", "CWE-94", "CWE-77"],
        description="Execucao de comandos via shell, Python, PowerShell",
        severity_impact="P0",
        sa_agents=["L2.01-bandit", "L2.02-semgrep-python"],
    ),
    "T1203": ATTACKTechnique(
        technique_id="T1203", name="Exploitation for Client Execution",
        tactic=ATTACKTactic.EXECUTION,
        cwe_ids=["CWE-416", "CWE-787", "CWE-125", "CWE-119"],
        description="Explora memoria (UAF, buffer overflow) para execucao de codigo",
        severity_impact="P0",
        sa_agents=["L2.09-cppcheck", "L2.10-codeql-cpp"],
    ),
    "T1053": ATTACKTechnique(
        technique_id="T1053", name="Scheduled Task/Job",
        tactic=ATTACKTactic.EXECUTION,
        cwe_ids=["CWE-276", "CWE-732"],
        description="Persistencia via tarefas agendadas com permissoes incorretas",
        severity_impact="P1",
    ),

    # ── Persistence ──
    "T1547": ATTACKTechnique(
        technique_id="T1547", name="Boot or Logon Autostart Execution",
        tactic=ATTACKTactic.PERSISTENCE,
        cwe_ids=["CWE-276", "CWE-732", "CWE-269"],
        description="Modificacao de config de boot para persistencia",
        severity_impact="P1",
    ),
    "T1543": ATTACKTechnique(
        technique_id="T1543", name="Create or Modify System Process",
        tactic=ATTACKTactic.PERSISTENCE,
        cwe_ids=["CWE-276", "CWE-250"],
        description="Criacao de servico do sistema para execucao persistente",
        severity_impact="P1",
    ),

    # ── Privilege Escalation ──
    "T1068": ATTACKTechnique(
        technique_id="T1068", name="Exploitation for Privilege Escalation",
        tactic=ATTACKTactic.PRIVILEGE_ESCALATION,
        cwe_ids=["CWE-269", "CWE-250", "CWE-732", "CWE-416"],
        description="Explora vulnerabilidade para obter privilegios elevados",
        severity_impact="P0",
    ),
    "T1548": ATTACKTechnique(
        technique_id="T1548", name="Abuse Elevation Control Mechanism",
        tactic=ATTACKTactic.PRIVILEGE_ESCALATION,
        cwe_ids=["CWE-276", "CWE-250", "CWE-863"],
        description="Bypass de controle de elevacao (sudo, UAC, setuid)",
        severity_impact="P0",
        sa_agents=["L2.24-checkov", "L2.25-tfsec"],
    ),

    # ── Defense Evasion ──
    "T1027": ATTACKTechnique(
        technique_id="T1027", name="Obfuscated Files or Information",
        tactic=ATTACKTactic.DEFENSE_EVASION,
        cwe_ids=["CWE-506"],
        description="Codigo ofuscado para evitar deteccao (base64, XOR, packing)",
        severity_impact="P1",
    ),
    "T1562": ATTACKTechnique(
        technique_id="T1562", name="Impair Defenses",
        tactic=ATTACKTactic.DEFENSE_EVASION,
        cwe_ids=["CWE-276", "CWE-732"],
        description="Desabilitar firewall, antivirus, logging",
        severity_impact="P1",
    ),
    "T1070": ATTACKTechnique(
        technique_id="T1070", name="Indicator Removal",
        tactic=ATTACKTactic.DEFENSE_EVASION,
        cwe_ids=["CWE-276", "CWE-532"],
        description="Remocao de logs e evidencias de comprometimento",
        severity_impact="P1",
    ),

    # ── Credential Access ──
    "T1003": ATTACKTechnique(
        technique_id="T1003", name="OS Credential Dumping",
        tactic=ATTACKTactic.CREDENTIAL_ACCESS,
        cwe_ids=["CWE-522", "CWE-256", "CWE-257", "CWE-798"],
        description="Extracao de credenciais do sistema (LSASS, /etc/shadow)",
        severity_impact="P0",
        sa_agents=["L2.28-gitleaks", "L2.29-trufflehog"],
    ),
    "T1552": ATTACKTechnique(
        technique_id="T1552", name="Unsecured Credentials",
        tactic=ATTACKTactic.CREDENTIAL_ACCESS,
        cwe_ids=["CWE-798", "CWE-312", "CWE-313", "CWE-200", "CWE-532"],
        description="Credenciais em texto claro (codigo fonte, logs, configs)",
        severity_impact="P0",
        sa_agents=["L2.28-gitleaks", "L2.29-trufflehog", "L2.01-bandit"],
    ),
    "T1110": ATTACKTechnique(
        technique_id="T1110", name="Brute Force",
        tactic=ATTACKTactic.CREDENTIAL_ACCESS,
        cwe_ids=["CWE-307", "CWE-521"],
        description="Tentativas repetidas de autenticacao sem rate limiting",
        severity_impact="P1",
    ),
    "T1555": ATTACKTechnique(
        technique_id="T1555", name="Credentials from Password Stores",
        tactic=ATTACKTactic.CREDENTIAL_ACCESS,
        cwe_ids=["CWE-798", "CWE-312", "CWE-256"],
        description="Extracao de credenciais de keychain, vault, password manager",
        severity_impact="P0",
    ),

    # ── Discovery ──
    "T1082": ATTACKTechnique(
        technique_id="T1082", name="System Information Discovery",
        tactic=ATTACKTactic.DISCOVERY,
        cwe_ids=["CWE-200", "CWE-201"],
        description="Coleta de informacao do sistema (hostname, OS, patches)",
        severity_impact="P2",
    ),
    "T1046": ATTACKTechnique(
        technique_id="T1046", name="Network Service Discovery",
        tactic=ATTACKTactic.DISCOVERY,
        cwe_ids=["CWE-200"],
        description="Scan de portas e servicos na rede",
        severity_impact="P2",
    ),

    # ── Lateral Movement ──
    "T1210": ATTACKTechnique(
        technique_id="T1210", name="Exploitation of Remote Services",
        tactic=ATTACKTactic.LATERAL_MOVEMENT,
        cwe_ids=["CWE-89", "CWE-78", "CWE-502", "CWE-416"],
        description="Explora servico remoto para mover-se lateralmente",
        severity_impact="P0",
    ),
    "T1021": ATTACKTechnique(
        technique_id="T1021", name="Remote Services",
        tactic=ATTACKTactic.LATERAL_MOVEMENT,
        cwe_ids=["CWE-287", "CWE-306", "CWE-522"],
        description="Uso de RDP, SSH, SMB com credenciais comprometidas",
        severity_impact="P1",
    ),

    # ── Collection ──
    "T1005": ATTACKTechnique(
        technique_id="T1005", name="Data from Local System",
        tactic=ATTACKTactic.COLLECTION,
        cwe_ids=["CWE-200", "CWE-538", "CWE-359"],
        description="Coleta de dados sensiveis do sistema local",
        severity_impact="P1",
    ),

    # ── Command and Control ──
    "T1071": ATTACKTechnique(
        technique_id="T1071", name="Application Layer Protocol",
        tactic=ATTACKTactic.COMMAND_AND_CONTROL,
        cwe_ids=["CWE-918", "CWE-319"],
        description="Uso de HTTP/HTTPS/DNS para C2 (SSRF pode ser vetor)",
        severity_impact="P1",
    ),
    "T1573": ATTACKTechnique(
        technique_id="T1573", name="Encrypted Channel",
        tactic=ATTACKTactic.COMMAND_AND_CONTROL,
        cwe_ids=["CWE-327", "CWE-295", "CWE-297"],
        description="Criptografia fraca permite interceptacao do canal C2",
        severity_impact="P1",
    ),

    # ── Exfiltration ──
    "T1048": ATTACKTechnique(
        technique_id="T1048", name="Exfiltration Over Alternative Protocol",
        tactic=ATTACKTactic.EXFILTRATION,
        cwe_ids=["CWE-200", "CWE-359", "CWE-319"],
        description="Exfiltracao de dados via DNS, ICMP, ou protocolos nao-monitorados",
        severity_impact="P0",
    ),

    # ── Impact ──
    "T1485": ATTACKTechnique(
        technique_id="T1485", name="Data Destruction",
        tactic=ATTACKTactic.IMPACT,
        cwe_ids=["CWE-276", "CWE-732"],
        description="Destruicao de dados (ransomware, wiper)",
        severity_impact="P0",
    ),
    "T1499": ATTACKTechnique(
        technique_id="T1499", name="Endpoint Denial of Service",
        tactic=ATTACKTactic.IMPACT,
        cwe_ids=["CWE-400", "CWE-770", "CWE-834"],
        description="DoS via consumo de recursos (CPU, memoria, file descriptors)",
        severity_impact="P1",
    ),
}


# ── Query Functions ───────────────────────────────────────────────

def get_techniques_for_cwe(cwe_id: str) -> list[ATTACKTechnique]:
    """Return all ATT&CK techniques mapped to a CWE."""
    return [t for t in ATTACK_CATALOG.values() if cwe_id in t.cwe_ids]

def get_techniques_by_tactic(tactic: ATTACKTactic) -> list[ATTACKTechnique]:
    """Return all techniques for a given tactic."""
    return [t for t in ATTACK_CATALOG.values() if t.tactic == tactic]

def get_severity_boost(cwe_ids: list[str]) -> float:
    """Calculate severity boost based on ATT&CK mapping.
    Multiple P0 techniques → higher boost.
    """
    boost = 0.0
    for cwe_id in cwe_ids:
        techniques = get_techniques_for_cwe(cwe_id)
        for t in techniques:
            if t.severity_impact == "P0":
                boost += 0.5
            elif t.severity_impact == "P1":
                boost += 0.25
    return min(3.0, boost)  # Cap at 3.0
