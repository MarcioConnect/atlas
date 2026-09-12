from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from atlas.config import Settings

PROFILE_NAME = "atlas"
DEFAULT_MODEL = "nemotron-3-ultra-free"
PROFILE_VERSION = "7"

ATLAS_SKIN = r'''name: atlas
description: ATLAS cyber minimalista
colors:
  banner_border: "#163A59"
  banner_title: "#FFFFFF"
  banner_accent: "#2F6B9A"
  banner_dim: "#526A7D"
  banner_text: "#EEEEEE"
  ui_accent: "#2F6B9A"
  ui_label: "#CCCCCC"
  ui_ok: "#DDDDDD"
  ui_error: "#FFFFFF"
  ui_warn: "#BBBBBB"
  prompt: "#FFFFFF"
  input_rule: "#163A59"
  response_border: "#2F6B9A"
  status_bar_bg: "#050B12"
  status_bar_text: "#BBBBBB"
  status_bar_strong: "#6F9FC4"
  status_bar_dim: "#526A7D"
  status_bar_good: "#DDDDDD"
  status_bar_warn: "#BBBBBB"
  status_bar_bad: "#FFFFFF"
  status_bar_critical: "#FFFFFF"
  session_label: "#CCCCCC"
  session_border: "#163A59"
  completion_menu_bg: "#050B12"
  completion_menu_current_bg: "#10283D"
  selection_bg: "#163A59"
  shell_dollar: "#6F9FC4"
  voice_status_bg: "#050B12"
light_colors:
  status_bar_bg: "#FFFFFF"
  status_bar_text: "#222222"
  prompt: "#111111"
  banner_text: "#111111"
  completion_menu_bg: "#FFFFFF"
  completion_menu_current_bg: "#DDDDDD"
  selection_bg: "#CCCCCC"
branding:
  agent_name: "ATLAS"
  welcome: "ATLAS online. Digite sua mensagem ou /help para ver os comandos."
  goodbye: "ATLAS offline."
  response_label: " ▲ ATLAS "
  prompt_symbol: "⚕"
  help_header: "ATLAS · Comandos disponíveis"
spinner:
  waiting_faces: ["/\\", "△", "▲"]
  thinking_faces: ["/\\", "△", "▲"]
  waiting_verbs: ["observando", "correlacionando", "verificando"]
  thinking_verbs: ["analisando", "investigando", "mapeando riscos"]
tool_prefix: "┊"
banner_logo: |2-
            ╭──────────────────╮
         ╭──╯                  ╰──╮
        ╱       ╭──────────╮       ╲
       │       │     ╱╲     │       │
       │       │    ╱  ╲    │       │
       │       │   ╱ ╱╲ ╲   │       │
       │       │  ╱ ╱  ╲ ╲  │       │
        ╲       ╰──────────╯       ╱
         ╰──╮                  ╭──╯
            ╰──────────────────╯

                 A T L A S
             AI SECURITY AGENT
banner_hero: |2-
          /\
         /  \
        / /\ \
       //  \\
'''

# Override the upstream logo in the ATLAS profile with the requested symbol.
ATLAS_SKIN += '\nbanner_logo: |2-\n              ⚕  A T L A S\n             SECURITY AGENT\n'

ATLAS_SOUL = """# ATLAS

Você é o ATLAS, um agente inteligente de terminal para engenharia de software,
administração e segurança defensiva. Responda em português, salvo pedido contrário.
Seja direto, profissional e investigue fatos com as ferramentas disponíveis antes
de concluir.

Analise código, configurações, dependências, testes, processos, portas, serviços,
containers e histórico operacional quando forem relevantes. Para a análise
estruturada da máquina, execute `atlas security --format json`. Para atividades
anteriores, consulte `atlas history` e `atlas monitor events`. Correlacione findings reais com alterações no
projeto e explique evidência, risco, componente afetado e recomendação.

Você é somente leitura por padrão. Peça confirmação antes de editar arquivos,
instalar software, reiniciar serviços, alterar containers ou executar qualquer ação
que mude o sistema. Nunca explore vulnerabilidades nem contorne controles. Nunca
mostre ou persista senhas, tokens, chaves e credenciais; substitua-os por
`[REDACTED]`. Não leia arquivos de secrets sem necessidade e autorização explícita.
"""


def find_hermes() -> str | None:
    candidates = [
        shutil.which("hermes"),
        str(Path(os.environ.get("LOCALAPPDATA", "")) / "hermes" / "bin" / "hermes.exe")
        if os.environ.get("LOCALAPPDATA")
        else None,
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    return None


def hermes_root() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "hermes"
    return Path.home() / ".hermes"


def profile_dir() -> Path:
    return hermes_root() / "profiles" / PROFILE_NAME


def _run_setup(executable: str, arguments: list[str]) -> None:
    result = subprocess.run(
        [executable, "--profile", PROFILE_NAME, *arguments],
        text=True,
        capture_output=True,
        check=False,
        shell=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"Falha ao configurar o perfil ATLAS: {detail or result.returncode}")


def ensure_agent_profile(executable: str) -> Path:
    target = profile_dir()
    if not (target / "config.yaml").exists():
        result = subprocess.run(
            [executable, "profile", "create", PROFILE_NAME, "--no-alias", "--no-skills",
             "--description", "ATLAS: engenharia, administracao e seguranca defensiva."],
            text=True, capture_output=True, check=False, shell=False,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"Não foi possível criar o perfil ATLAS: {detail or result.returncode}")

    skins = target / "skins"
    skins.mkdir(parents=True, exist_ok=True)
    skin_path = skins / "atlas.yaml"
    if not skin_path.exists() or skin_path.read_text(encoding="utf-8", errors="replace") != ATLAS_SKIN:
        skin_path.write_text(ATLAS_SKIN, encoding="utf-8")

    soul_path = target / "SOUL.md"
    if not soul_path.exists() or "# ATLAS" not in soul_path.read_text(encoding="utf-8", errors="replace"):
        soul_path.write_text(ATLAS_SOUL, encoding="utf-8")

    version_path = target / ".atlas-profile-version"
    current = version_path.read_text(encoding="utf-8", errors="replace").strip() if version_path.exists() else ""
    if current != PROFILE_VERSION:
        _run_setup(executable, ["config", "set", "display.skin", "atlas"])
        _run_setup(executable, ["config", "set", "display.interface", "tui"])
        _run_setup(executable, ["config", "set", "security.redact_secrets", "true"])
        version_path.write_text(PROFILE_VERSION, encoding="utf-8")
    return target


def _normalize_model(model: str | None) -> str:
    selected = model or Settings.load().agent_model or DEFAULT_MODEL
    return selected.split("/", 1)[1] if selected.startswith("opencode/") else selected


def ensure_monitoring(target: Path) -> None:
    from atlas.monitor import is_running, start_background

    if not is_running():
        configured = [Path(path) for path in Settings.load().watch_paths]
        start_background(configured or [target])


def launch_agent(directory: Path | None = None, model: str | None = None, continue_session: bool = False) -> int:
    executable = find_hermes()
    if not executable:
        raise RuntimeError("O backend do agente não foi encontrado. Use `atlas dashboard` para o modo local.")
    ensure_agent_profile(executable)
    target = (directory or Path.cwd()).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        raise RuntimeError(f"Diretório inválido: {target}")

    # O observador é independente da conversa e continua ativo após a TUI fechar.
    ensure_monitoring(target)

    # Prefer the local Hermes Python checkout so ATLAS-specific banner control
    # is honored. Keep the packaged executable as a fallback for installations
    # that do not include the source checkout/virtualenv.
    hermes_root = Path(executable).parent.parent / "hermes-agent"
    hermes_python = hermes_root / "venv" / "Scripts" / "python.exe"
    hermes_cli = hermes_root / "cli.py"
    source_mode = hermes_python.exists() and hermes_cli.exists()
    command = [str(hermes_python), str(hermes_cli)] if source_mode else [executable]
    if source_mode:
        command += ["--provider", "opencode-free", "--model", _normalize_model(model)]
    else:
        command += ["--profile", PROFILE_NAME, "--provider", "opencode-free",
                    "--model", _normalize_model(model), "--tui", "--in", str(target)]
    if continue_session:
        command.extend(["--resume", "latest"])
    env = os.environ.copy()
    env["ATLAS_AGENT"] = "1"
    env["ATLAS_HIDE_HERMES_BANNER"] = "0"
    env["HERMES_PROFILE"] = PROFILE_NAME
    if source_mode:
        env["HERMES_HOME"] = str(profile_dir())
    try:
        return subprocess.call(command, cwd=target, env=env, shell=False)
    except OSError as exc:
        raise RuntimeError(f"Falha ao iniciar o agente ATLAS: {exc}") from exc
