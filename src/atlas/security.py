from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import socket
import stat
from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path

from atlas.config import Settings, data_dir
from atlas.database import Database
from atlas.file_scope import scoped_files
from atlas.models import Finding, Scan, Severity
from atlas.system import (
    common_server_configs,
    docker_inspect,
    listening_ports,
    powershell,
    run_readonly,
)

PENALTIES = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 7,
    Severity.LOW: 3,
    Severity.INFO: 0,
}
PENALTY_CAPS = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 30,
    Severity.MEDIUM: 20,
    Severity.LOW: 10,
    Severity.INFO: 0,
}

SENSITIVE_PATTERNS = [
    ("chave privada", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("token GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")),
    ("credencial em configuracao", re.compile(r"(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s$<{]{6,}")),
]

SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__", ".cache", "appdata",
    ".browser-check", ".tox", ".nox", "site-packages", "dist", "build", ".next", "coverage",
    ".vscode", ".idea", "docs", "documentation", "examples", "vendor", "third_party", "generated",
    ".review-", ".diag-",
}
TEXT_SUFFIXES = {
    ".txt", ".conf", ".cfg", ".ini", ".env", ".json", ".yaml", ".yml", ".toml", ".xml",
    ".py", ".js", ".ts", ".ps1", ".sh", ".service", ".properties",
}


def score_findings(findings: Iterable[Finding]) -> int:
    unique = {(finding.fingerprint, finding.severity): finding for finding in findings}
    by_severity: dict[Severity, int] = {level: 0 for level in PENALTIES}
    for item in unique.values():
        severity = Severity(item.severity)
        by_severity[severity] += PENALTIES[severity]
    penalty = sum(min(value, PENALTY_CAPS[level]) for level, value in by_severity.items())
    return max(0, 100 - penalty)


def redact(value: str) -> str:
    text = value
    text = re.sub(
        r"(?i)(password|passwd|pwd|token|secret|api[_-]?key|cookie|authorization|client[_-]?secret)"
        r"(\s*[:=]\s*)[^\s,;]+",
        r"\1\2[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)(https?://[^:/\s]+:)[^@/\s]+@", r"\1[REDACTED]@", text)
    text = re.sub(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"]+",
        "[REDACTED]",
        text,
    )
    text = re.sub(r"(?im)^\s*[A-Z][A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|KEY|COOKIE)[A-Z0-9_]*\s*=.*$", "[REDACTED]", text)
    text = re.sub(r"-----BEGIN[\s\S]{0,100}?PRIVATE KEY-----", "[REDACTED]", text)
    text = re.sub(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,})\b", "[REDACTED]", text)
    return text[:2000]


def finding(
    check_id: str,
    title: str,
    severity: Severity,
    evidence: str,
    risk: str,
    component: str,
    recommendation: str,
) -> Finding:
    safe_evidence = redact(evidence)
    safe_component = redact(component)[:255]
    fingerprint = hashlib.sha256(f"{check_id}|{safe_component}|{safe_evidence}".encode()).hexdigest()
    return Finding(
        check_id=check_id,
        title=title,
        severity=severity.value,
        evidence=safe_evidence,
        risk=redact(risk),
        component=safe_component,
        recommendation=redact(recommendation),
        fingerprint=fingerprint,
    )


class SecurityScanner:
    def __init__(self, database: Database | None = None, settings: Settings | None = None) -> None:
        self.database = database or Database()
        self.settings = settings or Settings.load()

    def scan(self, paths: list[Path] | None = None, persist: bool = True) -> Scan:
        findings: list[Finding] = []
        checks = [
            self._ports,
            self._firewall,
            self._ssh,
            self._docker,
            self._web_configs,
            self._software_versions,
        ]
        for check in checks:
            try:
                findings.extend(check())
            except Exception as exc:  # scanner must degrade safely
                findings.append(
                    finding(
                        "coverage",
                        "Verificacao incompleta",
                        Severity.INFO,
                        f"{check.__name__}: {type(exc).__name__}",
                        "Parte da superficie nao pode ser avaliada.",
                        check.__name__,
                        "Execute novamente com permissoes de leitura adequadas.",
                    )
                )
        roots = paths if paths is not None else self._default_secret_roots()
        findings.extend(self._permissions(roots))
        findings.extend(self._secrets(roots))
        scan = Scan(hostname=socket.gethostname(), score=score_findings(findings), findings=findings)
        if persist:
            self.database.save_scan(scan)
        return scan

    def _default_secret_roots(self) -> list[Path]:
        cwd = Path.cwd().resolve()
        home = Path.home().resolve()
        # Avoid implicit profile-wide scans; use --path for explicit project scope.
        if cwd == home:
            ssh = home / ".ssh"
            return [ssh] if ssh.exists() else []
        return [cwd]

    def _ports(self) -> list[Finding]:
        results: list[Finding] = []
        critical = {2375}
        high = {21, 23, 3306, 5432, 6379, 9200, 11211, 27017, 3389, 5985}
        medium = {135, 139, 445}
        listeners = listening_ports()
        seen: set[tuple[int, str]] = set()
        for item in listeners:
            # Compare observed listeners; this does not bind a socket.
            wildcard = item["host"] in {"0.0.0.0", "::"}  # nosec B104
            severity = Severity.INFO
            title = "Porta local em escuta"
            identity = (item["port"], item["process"])
            if identity in seen:
                continue
            seen.add(identity)
            if wildcard and item["port"] in critical:
                severity, title = Severity.CRITICAL, "Interface administrativa sem TLS potencialmente exposta"
            elif wildcard and item["port"] in high:
                severity, title = Severity.HIGH, "Servico sensivel exposto em todas as interfaces"
            elif wildcard and item["port"] in medium:
                severity, title = Severity.MEDIUM, "Servico de sistema exposto em todas as interfaces"
            elif wildcard:
                title = "Porta em escuta em todas as interfaces"
            results.append(
                finding(
                    "open-port",
                    title,
                    severity,
                    f"{item['host']}:{item['port']} LISTEN pid={item['pid'] or '-'} processo={item['process']}",
                    "Um listener pode ampliar a superficie de ataque, conforme rede e firewall.",
                    f"{item['process']}:{item['port']}",
                    "Confirme a necessidade do listener e restrinja bind e firewall ao minimo necessario.",
                )
            )
        if not listeners:
            results.append(finding("ports-coverage", "Nenhuma porta detectada", Severity.INFO, "psutil nao retornou listeners", "Acesso pode estar restrito.", "rede", "No Windows, tente PowerShell como Administrator para obter cobertura completa."))
        return results

    def _firewall(self) -> list[Finding]:
        results: list[Finding] = []
        if os.name == "nt":
            result = powershell("Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress")
            if not result.ok:
                return [finding("firewall-coverage", "Estado do firewall indisponivel", Severity.INFO, result.stderr or "consulta falhou", "Nao foi possivel confirmar a protecao de rede.", "Windows Firewall", "Verifique manualmente Get-NetFirewallProfile; PowerShell como Administrator pode ser necessario.")]
            disabled = re.findall(r'"Name":"([^"]+)"\s*,\s*"Enabled":false', result.stdout, re.IGNORECASE)
            for profile in disabled:
                results.append(finding("firewall-disabled", "Perfil de firewall desativado", Severity.HIGH, f"Perfil {profile}: Enabled=False", "Conexoes de entrada podem nao ser filtradas.", f"Windows Firewall/{profile}", "Ative o perfil apos validar as regras necessarias."))
            return results
        for command in (["ufw", "status"], ["firewall-cmd", "--state"], ["nft", "list", "ruleset"]):
            result = run_readonly(command)
            if result.ok:
                output = result.stdout.lower()
                if command[0] == "ufw" and "inactive" in output:
                    return [finding("firewall-disabled", "Firewall UFW inativo", Severity.HIGH, "Status: inactive", "O host pode aceitar trafego sem filtragem local.", "ufw", "Ative uma politica de firewall apropriada.")]
                return []
        return [finding("firewall-coverage", "Firewall nao identificado", Severity.INFO, "ufw/firewalld/nftables indisponiveis ou inacessiveis", "A protecao local nao pode ser confirmada.", "firewall", "Confirme manualmente a politica de firewall do host.")]

    def _ssh(self) -> list[Finding]:
        paths = [path for path in common_server_configs() if path.name == "sshd_config"]
        results: list[Finding] = []
        for path in paths:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rules = [
                (r"(?im)^\s*PermitRootLogin\s+yes\b", "Login SSH direto de root permitido", Severity.HIGH, "Use PermitRootLogin no ou prohibit-password."),
                (r"(?im)^\s*PermitEmptyPasswords\s+yes\b", "SSH permite senhas vazias", Severity.CRITICAL, "Defina PermitEmptyPasswords no."),
                (r"(?im)^\s*PasswordAuthentication\s+yes\b", "SSH aceita autenticacao por senha", Severity.MEDIUM, "Prefira chaves e defina PasswordAuthentication no quando viavel."),
            ]
            for pattern, title, severity, recommendation in rules:
                if re.search(pattern, content):
                    results.append(finding("ssh-config", title, severity, f"Diretiva insegura em {path}", "A configuracao facilita acesso indevido ou ataques de credenciais.", str(path), recommendation))
        return results

    def _docker(self) -> list[Finding]:
        results: list[Finding] = []
        for container in docker_inspect():
            name = str(container.get("Name", "container")).lstrip("/")
            host = container.get("HostConfig") or {}
            config = container.get("Config") or {}
            if host.get("Privileged"):
                results.append(finding("docker-privileged", "Container privilegiado", Severity.CRITICAL, f"{name}: Privileged=true", "Comprometimento do container pode alcançar o host.", name, "Remova --privileged e conceda somente capacidades indispensaveis."))
            user = str(config.get("User") or "root")
            if user in {"", "0", "root", "0:0", "root:root"}:
                results.append(finding("docker-root", "Container executa como root", Severity.HIGH, f"{name}: usuario efetivo root/default", "Uma falha no processo tera privilegios elevados dentro do container.", name, "Defina USER nao-root na imagem ou user no runtime."))
            for mount in container.get("Mounts") or []:
                source = str(mount.get("Source", "")).replace("\\", "/").lower()
                if source.endswith(("/docker.sock", "/pipe/docker_engine")):
                    results.append(finding("docker-socket", "Docker socket montado em container", Severity.CRITICAL, f"{name}: socket do Docker montado", "O container pode controlar o daemon e o host.", name, "Remova o mount; use uma API intermediaria com autorizacao minima."))
        return results

    def _web_configs(self) -> list[Finding]:
        results: list[Finding] = []
        ports = listening_ports()
        has_http = any(item["port"] == 80 for item in ports)
        has_https = any(item["port"] == 443 for item in ports)
        if has_http and not has_https:
            results.append(finding("http-without-https", "HTTP ativo sem listener HTTPS", Severity.MEDIUM, "Porta 80 em escuta; porta 443 nao detectada", "Dados podem trafegar sem confidencialidade e autenticidade.", "servidor web", "Configure TLS e redirecione HTTP para HTTPS."))
        for path in [p for p in common_server_configs() if p.name != "sshd_config"]:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if re.search(r"(?im)^\s*server_tokens\s+on", content) or re.search(r"(?im)^\s*ServerTokens\s+(Full|OS)", content):
                results.append(finding("web-version-banner", "Servidor web expoe detalhes de versao", Severity.LOW, f"Diretiva de banner permissiva em {path}", "Banners detalhados auxiliam reconhecimento de versoes.", str(path), "Desative server_tokens ou use ServerTokens Prod."))
            if re.search(r"(?im)^\s*autoindex\s+on", content) or re.search(r"(?im)^\s*Options\s+.*Indexes", content):
                results.append(finding("web-directory-listing", "Listagem de diretorio habilitada", Severity.MEDIUM, f"Diretiva encontrada em {path}", "Arquivos nao destinados ao publico podem ser enumerados.", str(path), "Desative autoindex/Indexes salvo necessidade documentada."))
        return results

    def _permissions(self, roots: list[Path]) -> list[Finding]:
        if os.name == "nt":
            results: list[Finding] = []
            denied = False
            for path in roots[:20]:
                if not path.exists():
                    continue
                result = run_readonly(["icacls", str(path)], timeout=5)
                if result.ok and re.search(r"(?i)(Everyone|Todos):\([^)]*[FMW]", result.stdout):
                    results.append(finding("dangerous-permission", "Permissao ampla de escrita", Severity.HIGH, f"ACL ampla detectada em {path}", "Usuarios nao confiaveis podem alterar dados ou configuracoes.", str(path), "Remova escrita de Everyone/Todos e aplique menor privilegio."))
                elif not result.ok:
                    denied = True
            if denied:
                results.append(finding("permissions-coverage", "Algumas ACLs nao puderam ser analisadas", Severity.INFO, "icacls retornou acesso negado ou consulta indisponivel", "A cobertura de permissoes esta parcial.", "Windows ACL", "Execute PowerShell como Administrator somente se precisar analisar caminhos protegidos."))
            return results
        results = []
        for root in roots[:20]:
            try:
                mode = root.stat().st_mode
                if mode & stat.S_IWOTH:
                    results.append(finding("dangerous-permission", "Caminho gravavel por qualquer usuario", Severity.HIGH, f"{root}: mode={oct(stat.S_IMODE(mode))}", "Outro usuario local pode alterar o conteudo.", str(root), "Remova a permissao de escrita para others."))
            except OSError:
                continue
        return results

    def _secrets(self, roots: list[Path]) -> list[Finding]:
        results: list[Finding] = []
        visited = 0
        atlas_data = data_dir().resolve()
        for root in roots:
            if not root.exists():
                continue
            root_resolved = root.resolve()
            candidates = scoped_files(root, SKIP_DIRS)
            for path in candidates:
                if visited >= self.settings.secret_scan_max_files:
                    return results
                try:
                    resolved = path.resolve()
                    relative_parts = resolved.relative_to(root_resolved).parts
                    ignored = any(
                        part.casefold() in SKIP_DIRS
                        or part.casefold().startswith((".pytest", ".test-", ".build-", ".publish-test-", ".review-", ".diag-"))
                        for part in relative_parts
                    )
                    if not path.is_file() or ignored:
                        continue
                    if atlas_data in resolved.parents or resolved.stat().st_size > self.settings.secret_scan_max_bytes:
                        continue
                    if path.suffix.lower() not in TEXT_SUFFIXES and not path.name.lower().startswith(".env"):
                        continue
                    visited += 1
                    content = path.read_text(encoding="utf-8", errors="replace")
                except (OSError, UnicodeError, ValueError):
                    continue
                for kind, pattern in SENSITIVE_PATTERNS:
                    match = pattern.search(content)
                    if match:
                        line = content.count("\n", 0, match.start()) + 1
                        results.append(finding("exposed-secret", "Possivel credencial em texto claro", Severity.HIGH, f"Padrao {kind} detectado em {path}:{line}; valor omitido", "Credenciais em arquivos podem ser copiadas ou publicadas acidentalmente.", str(path), "Revogue se necessario, mova para armazenamento seguro e restrinja permissoes."))
                        break
        return results

    def _software_versions(self) -> list[Finding]:
        rule_path = files("atlas").joinpath("rules/software_versions.json")
        rules = json.loads(rule_path.read_text(encoding="utf-8"))
        results: list[Finding] = []
        for rule in rules:
            product = rule["product"]
            version_output = platform.python_version() if product == "python" else ""
            for command in rule["commands"]:
                executable = shutil.which(command[0])
                if not executable:
                    continue
                probe = run_readonly([executable, *command[1:]])
                version_output = probe.stdout or probe.stderr
                if version_output:
                    break
            numbers = tuple(int(part) for part in re.findall(r"\d+", version_output)[:2])
            minimum = tuple(int(part) for part in rule["minimum"].split("."))
            if numbers and numbers < minimum:
                version = ".".join(str(part) for part in numbers)
                results.append(finding("software-version", "Software potencialmente desatualizado", Severity.MEDIUM, f"{product} {version}: regra heuristica offline ({rule['label']})", "Versoes antigas podem nao receber correcoes de seguranca.", product, "Valide o ciclo de suporte e os backports do fornecedor antes de planejar a atualizacao."))
        return results
