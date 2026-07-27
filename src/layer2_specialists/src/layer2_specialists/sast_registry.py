"""L2 — SAST Agent Registry.

Declarative configuration for all 30+ SAST agents.
Each agent entry defines: tool, command, output format, severity mapping.
No LLM — purely deterministic configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SASTOutputFormat(str, Enum):
    SARIF = "SARIF"
    JSON = "JSON"
    XML = "XML"
    TEXT = "TEXT"


@dataclass
class SASTAgentConfig:
    """Configuration for a single SAST agent."""
    agent_id: str
    name: str
    tool: str
    language: str
    command: list[str]
    output_format: SASTOutputFormat
    severity_map: dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 300
    enabled: bool = True
    description: str = ""


# ── Agent Registry ─────────────────────────────────────────────────────────

SAST_REGISTRY: dict[str, SASTAgentConfig] = {
    # Python
    "L2.01-bandit": SASTAgentConfig(
        agent_id="L2.01-bandit", name="Bandit", tool="bandit",
        language="python",
        command=["bandit", "-r", "{target}", "-f", "json", "-ll"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"HIGH": "P0", "MEDIUM": "P2", "LOW": "P3"},
        description="Python AST-based security linter",
    ),
    "L2.02-semgrep-python": SASTAgentConfig(
        agent_id="L2.02-semgrep-python", name="Semgrep Python", tool="semgrep",
        language="python",
        command=["semgrep", "--config=auto", "--lang=python", "--json", "{target}"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"ERROR": "P0", "WARNING": "P1", "INFO": "P3"},
        description="Multi-language static analysis (Python rules)",
    ),

    # Java
    "L2.03-spotbugs": SASTAgentConfig(
        agent_id="L2.03-spotbugs", name="SpotBugs", tool="spotbugs",
        language="java",
        command=["spotbugs", "-sarif", "-output", "{output_file}", "{target}"],
        output_format=SASTOutputFormat.SARIF,
        severity_map={"1": "P0", "2": "P2", "3": "P3"},
        description="Java bytecode static analysis",
    ),
    "L2.04-codeql-java": SASTAgentConfig(
        agent_id="L2.04-codeql-java", name="CodeQL Java", tool="codeql",
        language="java",
        command=["codeql", "database", "analyze", "{database}", "--format=sarif-latest", "--output={output_file}"],
        output_format=SASTOutputFormat.SARIF,
        severity_map={"error": "P0", "warning": "P1", "recommendation": "P3"},
        description="Semantic code analysis (Java)",
    ),

    # JavaScript / TypeScript
    "L2.05-eslint": SASTAgentConfig(
        agent_id="L2.05-eslint", name="ESLint", tool="eslint",
        language="javascript",
        command=["eslint", "{target}", "-f", "json"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"2": "P1", "1": "P3", "0": "P4"},
        timeout_seconds=120,
        description="JavaScript/TypeScript linter with security plugins",
    ),
    "L2.06-semgrep-js": SASTAgentConfig(
        agent_id="L2.06-semgrep-js", name="Semgrep JS/TS", tool="semgrep",
        language="javascript",
        command=["semgrep", "--config=auto", "--lang=javascript", "--json", "{target}"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"ERROR": "P0", "WARNING": "P1", "INFO": "P3"},
        description="Multi-language static analysis (JS/TS rules)",
    ),

    # Go
    "L2.07-gosec": SASTAgentConfig(
        agent_id="L2.07-gosec", name="gosec", tool="gosec",
        language="go",
        command=["gosec", "-fmt=json", "{target}/..."],
        output_format=SASTOutputFormat.JSON,
        severity_map={"HIGH": "P0", "MEDIUM": "P2", "LOW": "P3"},
        description="Go security checker",
    ),
    "L2.08-codeql-go": SASTAgentConfig(
        agent_id="L2.08-codeql-go", name="CodeQL Go", tool="codeql",
        language="go",
        command=["codeql", "database", "analyze", "{database}", "--format=sarif-latest", "--output={output_file}"],
        output_format=SASTOutputFormat.SARIF,
        severity_map={"error": "P0", "warning": "P1"},
        description="Semantic code analysis (Go)",
    ),

    # C / C++
    "L2.09-cppcheck": SASTAgentConfig(
        agent_id="L2.09-cppcheck", name="Cppcheck", tool="cppcheck",
        language="cpp",
        command=["cppcheck", "--enable=all", "--xml", "{target}", "2>{output_file}"],
        output_format=SASTOutputFormat.XML,
        severity_map={"error": "P0", "warning": "P2", "style": "P3"},
        timeout_seconds=600,
        description="C/C++ static analysis",
    ),
    "L2.10-codeql-cpp": SASTAgentConfig(
        agent_id="L2.10-codeql-cpp", name="CodeQL C/C++", tool="codeql",
        language="cpp",
        command=["codeql", "database", "analyze", "{database}", "--format=sarif-latest", "--output={output_file}"],
        output_format=SASTOutputFormat.SARIF,
        severity_map={"error": "P0", "warning": "P1"},
        description="Semantic code analysis (C/C++)",
    ),

    # Rust
    "L2.11-clippy": SASTAgentConfig(
        agent_id="L2.11-clippy", name="Clippy", tool="cargo-clippy",
        language="rust",
        command=["cargo", "clippy", "--message-format=json"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"error": "P0", "warning": "P2"},
        description="Rust linter with security lints",
    ),

    # C#
    "L2.12-roslyn": SASTAgentConfig(
        agent_id="L2.12-roslyn", name="Roslyn Analyzers", tool="dotnet",
        language="csharp",
        command=["dotnet", "build", "/p:GenerateSarifFile=true"],
        output_format=SASTOutputFormat.SARIF,
        severity_map={"error": "P0", "warning": "P2"},
        description="C# Roslyn security analyzers",
    ),

    # PHP
    "L2.13-psalm": SASTAgentConfig(
        agent_id="L2.13-psalm", name="Psalm", tool="psalm",
        language="php",
        command=["psalm", "--output-format=json", "{target}"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"error": "P1", "warning": "P3"},
        description="PHP static analysis with taint tracking",
    ),

    # Ruby
    "L2.14-brakeman": SASTAgentConfig(
        agent_id="L2.14-brakeman", name="Brakeman", tool="brakeman",
        language="ruby",
        command=["brakeman", "{target}", "-f", "json"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"High": "P0", "Medium": "P2", "Low": "P3"},
        description="Ruby on Rails security scanner",
    ),

    # Kotlin
    "L2.15-detekt": SASTAgentConfig(
        agent_id="L2.15-detekt", name="Detekt", tool="detekt",
        language="kotlin",
        command=["detekt", "--input", "{target}", "--report", "sarif:{output_file}"],
        output_format=SASTOutputFormat.SARIF,
        severity_map={"error": "P0", "warning": "P2"},
        description="Kotlin static analysis",
    ),

    # Swift
    "L2.16-swiftlint": SASTAgentConfig(
        agent_id="L2.16-swiftlint", name="SwiftLint", tool="swiftlint",
        language="swift",
        command=["swiftlint", "lint", "--reporter", "json", "{target}"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"error": "P1", "warning": "P3"},
        description="Swift linter",
    ),

    # SCA / Dependencies
    "L2.21-syft": SASTAgentConfig(
        agent_id="L2.21-syft", name="Syft SBOM", tool="syft",
        language="all",
        command=["syft", "{target}", "-o", "json"],
        output_format=SASTOutputFormat.JSON,
        description="Software Bill of Materials generator",
    ),
    "L2.22-nvd-correlator": SASTAgentConfig(
        agent_id="L2.22-nvd-correlator", name="NVD CVE Correlator", tool="grype",
        language="all",
        command=["grype", "dir:{target}", "-o", "json"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"Critical": "P0", "High": "P1", "Medium": "P2", "Low": "P3"},
        timeout_seconds=600,
        description="CVE vulnerability scanner (NVD + OSV + GHSA)",
    ),

    # IaC
    "L2.24-checkov": SASTAgentConfig(
        agent_id="L2.24-checkov", name="Checkov", tool="checkov",
        language="terraform",
        command=["checkov", "-d", "{target}", "-o", "json"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3"},
        description="IaC security scanner (Terraform, CloudFormation, K8s)",
    ),
    "L2.25-tfsec": SASTAgentConfig(
        agent_id="L2.25-tfsec", name="tfsec", tool="tfsec",
        language="terraform",
        command=["tfsec", "{target}", "--format=json", "--no-color"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P4"},
        description="Terraform security scanner",
    ),

    # Docker / Containers
    "L2.26-hadolint": SASTAgentConfig(
        agent_id="L2.26-hadolint", name="Hadolint", tool="hadolint",
        language="dockerfile",
        command=["hadolint", "{target}", "-f", "json"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"error": "P1", "warning": "P2", "info": "P4"},
        description="Dockerfile linter",
    ),

    # Kubernetes
    "L2.27-kubesec": SASTAgentConfig(
        agent_id="L2.27-kubesec", name="Kubesec", tool="kubesec",
        language="kubernetes",
        command=["kubesec", "scan", "{target}"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"critical": "P0", "high": "P1", "medium": "P3"},
        description="Kubernetes security scanner",
    ),

    # Secrets
    "L2.28-gitleaks": SASTAgentConfig(
        agent_id="L2.28-gitleaks", name="Gitleaks", tool="gitleaks",
        language="all",
        command=["gitleaks", "detect", "--source={target}", "--report-format=json", "--report-path={output_file}"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"HIGH": "P0", "MEDIUM": "P1", "LOW": "P3"},
        description="Secret scanner — API keys, tokens, passwords",
    ),
    "L2.29-trufflehog": SASTAgentConfig(
        agent_id="L2.29-trufflehog", name="TruffleHog", tool="trufflehog",
        language="all",
        command=["trufflehog", "filesystem", "{target}", "--json"],
        output_format=SASTOutputFormat.JSON,
        severity_map={"HIGH": "P0", "MEDIUM": "P1"},
        timeout_seconds=600,
        description="Secret scanner — verified credentials",
    ),
}


def get_agents_for_language(language: str) -> list[SASTAgentConfig]:
    """Return language-specific SAST agents (excludes cross-cutting 'all')."""
    agents = []
    for agent_id, config in SAST_REGISTRY.items():
        if config.language == language and config.enabled:
            agents.append(config)
    return agents


def get_cross_cutting_agents() -> list[SASTAgentConfig]:
    """Return always-run agents (secrets, SCA)."""
    return [
        config for config in SAST_REGISTRY.values()
        if config.language == "all" and config.enabled
    ]
