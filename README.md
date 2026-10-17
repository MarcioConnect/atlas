# ATLAS v0.2.0

[![CI](https://github.com/MarcioConnect/atlas/actions/workflows/ci.yml/badge.svg)](https://github.com/MarcioConnect/atlas/actions/workflows/ci.yml)
[![CodeQL](https://github.com/MarcioConnect/atlas/actions/workflows/codeql.yml/badge.svg)](https://github.com/MarcioConnect/atlas/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/MarcioConnect/atlas)](https://github.com/MarcioConnect/atlas/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6.svg)](#requisitos)

> Agente defensivo de terminal para Windows.

O ATLAS observa projetos escolhidos, analisa código alterado com scanners locais
e destaca riscos novos sem depender de Codex, editor ou IA. Mantém histórico e
mostra quando um scan ficou incompleto.

```powershell
atlas scan "C:\MeuProjeto"        # análise pontual
atlas watch "C:\MeuProjeto"       # monitoramento no terminal
atlas monitor start               # monitora projetos salvos em segundo plano
```

`atlas` abre o painel; `atlas report --format html` gera um relatório.
Ollama é opcional e só analisa dados mediante solicitação. O ATLAS não explora
falhas, não substitui o Microsoft Defender e não garante ausência de
vulnerabilidades.

![ATLAS Security Watchdog TUI](docs/screenshots/atlas-watchdog.png)

## Sumário

- [Sobre](#sobre)
- [Download rápido (Windows)](#download-rápido-windows)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Início rápido](#início-rápido)
- [Primeira execução e diagnóstico](#primeira-execução-e-diagnóstico)
- [Monitoramento contínuo](#monitoramento-contínuo)
- [Scanners](#scanners)
- [Integração com CI](#integração-com-ci)
- [Suprimindo findings](#suprimindo-findings)
- [Configuração por projeto](#configuração-por-projeto)
- [Relatórios](#relatórios)
- [TUI do Watchdog](#tui-do-watchdog)
- [Arquivos suportados](#arquivos-suportados)
- [Ciclo de vida de findings](#ciclo-de-vida-de-findings)
- [Privacidade e segurança](#privacidade-e-segurança)
- [Limitações](#limitações)
- [Desenvolvimento](#desenvolvimento)
- [Contribuindo](#contribuindo)
- [Licença](#licença)

## Sobre

### Resultado confiável

Cada finding mostra severidade, confiança heurística e scanner. `RESOLVED` exige
que o scanner execute com sucesso e reanalise o arquivo/escopo; caso contrário,
o estado é `UNVERIFIED`. Scans parciais e scanners ausentes aparecem como lacunas
de cobertura. A baseline inicial não dispara alertas antigos como novos.

### Estado da versão

O fluxo arquivo alterado → debounce → scanner local → comparação → SQLite → TUI
foi validado em Windows. A suíte atual passa 2.794 testes em cada ambiente
isolado com Python 3.11 e 3.14. Os resultados e limites estão em
[`IMPLEMENTATION_REPORT.md`](IMPLEMENTATION_REPORT.md). Há também um teste que
consolida uma rajada de 1.000 eventos em um scan. Muitos casos são sintéticos e
não provam precisão em todos os projetos. Scanners externos continuam opcionais.

## Download rápido (Windows)

Quer apenas usar? Baixe o executável pronto na página da release:

**[Baixar ATLAS-Security-Agent.exe — v0.2.0](https://github.com/MarcioConnect/atlas/releases/download/v0.2.0/ATLAS-Security-Agent.exe)**

Depois, no PowerShell:

```powershell
.\ATLAS-Security-Agent.exe --version
.\ATLAS-Security-Agent.exe monitor start
```

A release inclui `ATLAS-Security-Agent.exe.sha256`. Verifique que o download não
foi corrompido antes de executar:

```powershell
$expected = (Get-Content .\ATLAS-Security-Agent.exe.sha256).Split(' ')[0]
$actual = (Get-FileHash .\ATLAS-Security-Agent.exe -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "ATLAS checksum mismatch" }
"ATLAS checksum OK"
```

O executável v0.2.0 não possui assinatura Authenticode; o Windows pode exibir um
aviso de publicador. Um checksum detecta corrupção, mas não prova por si só quem
publicou o arquivo. Consulte [`docs/SIGNING.md`](docs/SIGNING.md).

Não precisa instalar Python, Git ou abrir navegador. A logo usada pelo executável
está disponível em [`assets/atlas.ico`](assets/atlas.ico).

Para instalar como pacote Python e usar o comando `atlas`, siga a seção de
instalação abaixo.

## Requisitos

- Windows 10 ou Windows 11
- PowerShell 7 e Windows Terminal recomendados
- Python 3.11 ou superior
- Privilégios de Administrador **não** são necessários para analisar código-fonte

Scanners opcionais são detectados em tempo de execução. Ferramentas ausentes
nunca impedem o scanner ATLAS Native nem outro scanner disponível.

## Instalação

Para instalar a partir do ZIP do código-fonte, use **Code > Download ZIP** no
GitHub, extraia, abra o PowerShell na pasta e execute:

```powershell
py -m pip install .
atlas --version
```

Git não é necessário. Para atualizar uma cópia já instalada, use
`py -m pip install --upgrade .` a partir da pasta extraída mais recente.

Se a release do GitHub fornecer `ATLAS-Security-Agent.exe`, Python não é
necessário para o uso normal. Baixe o executável e execute:

```powershell
.\ATLAS-Security-Agent.exe --version
.\ATLAS-Security-Agent.exe monitor start
```

Para desenvolvimento:

```powershell
python -m pip install -e ".[dev]"
```

Para gerar o executável Windows autônomo com o ícone e a identidade de processo
do ATLAS:

```powershell
.\tools\build_windows.ps1
.\release\ATLAS-Security-Agent.exe monitor start
```

O monitor residente então aparece no Gerenciador de Tarefas como
`ATLAS-Security-Agent.exe`, com o ícone do ATLAS em vez de `python.exe`. O build
Windows em arquivo único pode aparecer como dois processos ATLAS agrupados
enquanto estiver ativo: o launcher do PyInstaller e o agente residente. Ambos
usam o nome e o ícone do ATLAS.

Notificações do Windows e scanners Python opcionais:

```powershell
python -m pip install ".[desktop]"
python -m pip install ".[python-scanners]"
```

A fonte da verdade das dependências de runtime é o `pyproject.toml`.

## Início rápido

Faça um scan pontual do projeto sem abrir a TUI de monitoramento:

```powershell
atlas scan
atlas scan "C:\Meu Projeto"
atlas scan "C:\Meu Projeto" --format json
```

O comando analisa o diretório atual por padrão. Ele lista findings ativos e avisa
quando scanners opcionais estão ausentes. Arquivos-fonte acima de 2 MB são
ignorados para limitar o uso de recursos; eles são contados e o resultado é
marcado como cobertura parcial, em vez de sugerir que o projeto foi totalmente
analisado.

Inicie o monitoramento contínuo com a visão interativa:

```powershell
atlas watch "C:\Meu Projeto"
```

Para monitorar continuamente todos os projetos salvos em segundo plano:

```powershell
atlas monitor start
atlas monitor status
```

O ATLAS abre uma TUI Textual no terminal atual. Mantenha-a em execução enquanto
usa qualquer editor ou agente de código. Alterações relevantes são agrupadas com
um debounce de dois segundos, analisadas localmente, reconciliadas com o SQLite
e exibidas como `NEW`, `EXISTING`, `RESOLVED` ou `UNVERIFIED`. Um finding só é
marcado como `RESOLVED` depois que o scanner tem sucesso e reexamina o
arquivo/escopo relevante. Um scanner com falha, parcial, indisponível ou
expirado deixa o finding anterior não verificado. A saúde do scan indica
`COMPLETE` ou `PARTIAL`; apenas instalar o scanner não conta como análise
concluída.

Para monitorar todos os caminhos de projeto existentes salvos no ATLAS, omita o
caminho ou use `--all`:

```powershell
atlas watch
atlas watch --all
```

A TUI multi-projeto mostra o status de cada projeto, contadores de scan e novos
findings em uma única tela. Se nenhum caminho estiver configurado, execute por
exemplo:

```powershell
atlas monitor start --watch "C:\Meu Projeto"
```

Execute um scan sem abrir a TUI:

```powershell
atlas watch "C:\Meu Projeto" --once
```

Habilite a revisão opcional de IA local com Ollama:

```powershell
winget install Ollama.Ollama
ollama pull qwen2.5-coder:3b
atlas watch "C:\Meu Projeto" --ai
```

`--ai` apenas habilita a capacidade de revisão. Os scans não chamam o modelo
automaticamente; selecione um finding na TUI e pressione `A` para solicitar uma
revisão explícita. O ATLAS envia trechos curtos e sanitizados do código
exclusivamente para `127.0.0.1:11434`, solicita JSON estruturado, não expõe
ferramentas ao modelo e nunca executa a saída do modelo. Use `--ai-model MODEL`
para selecionar outro modelo local.

Use `--silent` para manter o watcher silencioso, ou persista exclusões de regras
com `--ignore-rule`:

```powershell
atlas watch "C:\Meu Projeto" --silent
atlas watch "C:\Meu Projeto" --notify
atlas watch "C:\Meu Projeto" --ignore-rule hardcoded-secret
```

O Watchdog usa um snapshot de arquivos em memória para priorizar arquivos e
linhas alterados após a primeira observação. O scanner nativo reexamina cada
arquivo alterado por completo, para que um finding inalterado não seja marcado
falsamente como resolvido. Scanners opcionais permanecem limitados aos arquivos
alterados; scanners indisponíveis ou com falha são reportados sem interromper o
watch. Uma porta `LISTEN` é uma observação, não prova de acessibilidade externa.
A integração com o Defender é somente leitura durante scans normais e sua
visibilidade depende da política e das permissões do Windows. Quando o `winotify`
está instalado, novos findings também geram uma notificação de área de trabalho
do Windows; caso contrário, a TUI continua sendo a fonte da verdade.

## Primeira execução e diagnóstico

Em uma instalação nova, o ATLAS pode encontrar seus repositórios Git, escolher o
que monitorar, executar um primeiro scan e, opcionalmente, registrar o monitor em
segundo plano em uma única etapa:

```powershell
atlas init
atlas init --path "C:\Meu Projeto" --yes --no-scan
```

Quando algo não funcionar, execute `atlas doctor` para verificar Python, scanners
opcionais, Ollama local, o monitor residente, a tarefa de login do Windows e o
banco local. As falhas são listadas com uma correção sugerida; `atlas doctor
--no-fix` apenas reporta, sem perguntar.

O monitor residente grava um log com dados sensíveis removidos em
`%LOCALAPPDATA%\ATLAS\logs\monitor.log` (rotacionado uma vez para
`monitor.log.old`). Inspecione com:

```powershell
atlas monitor logs
atlas monitor logs --limit 200 --follow
```

## Monitoramento contínuo

`atlas monitor start` roda em segundo plano e inicia um Watchdog de código local
por caminho configurado existente. Todas as alterações de arquivos não ignorados
são registradas como metadados sanitizados; arquivos-fonte/configuração
suportados são agrupados por debounce, analisados localmente e reconciliados
como `NEW`/`EXISTING`/`RESOLVED`. A IA permanece opt-in com `atlas watch --ai`.
Use `atlas monitor status` e `atlas monitor events` para inspecionar o serviço
residente.

## Scanners

| Scanner | Escopo | Instalação opcional |
|---|---|---|
| ATLAS Native | Segredos, APIs arriscadas, binds expostos, noções básicas de Docker | Integrado |
| ATLAS Security Guard | Prompt injection, cadeias de exfiltração, ofuscação, abuso de ferramentas | Integrado |
| Microsoft Defender | Estado de malware/spyware e histórico de detecções no Windows | Integrado ao Windows |
| Executable inspection | SHA-256 em streaming e status Authenticode; não assinado não é prova de malware | Integrado ao Windows |
| YARA | Scan opcional com regras locais selecionadas e tempo de execução limitado | `py -m pip install 'atlas-security-agent[yara]'` |
| Ollama AI | Revisão explícita de um finding sanitizado selecionado ou de contexto de chat solicitado | `winget install Ollama.Ollama` |
| Semgrep | Análise estática multi-linguagem | `python -m pip install semgrep` |
| Bandit | Lint de segurança para Python | `python -m pip install bandit` |
| pip-audit | Dependências Python | `python -m pip install pip-audit` |
| npm audit | Dependências npm | Instale Node.js/npm |
| PSScriptAnalyzer | Análise de PowerShell | `Install-Module PSScriptAnalyzer -Scope CurrentUser` |
| Trivy | Dependências, contêineres, más configurações, segredos | `winget install AquaSecurity.Trivy` |

Alguns scanners de dependências podem precisar de acesso à rede para atualizar
bancos de avisos. Isso não envolve LLM nem tokens de IA.

## Integração com CI

`atlas scan --fail-on` retorna o código de saída `2` quando um finding atinge o
limite de severidade, permitindo bloquear um pipeline:

```powershell
atlas scan . --fail-on HIGH
atlas scan . --fail-on HIGH --format json
```

Para o code scanning do GitHub, gere SARIF e faça o upload:

```powershell
atlas report --format sarif --project . --output .\reports
```

Instale um hook `pre-commit` do Git que bloqueia commits com findings no nível ou
acima de um limite:

```powershell
atlas install-hook --project .
atlas install-hook --fail-on MEDIUM --force
```

Remova `.git/hooks/pre-commit` para desabilitar o hook.

## Suprimindo findings

Findings de risco aceito podem ser suprimidos pela CLI ou diretamente na TUI. Uma
supressão registra a fingerprint, um motivo sanitizado e uma expiração.

```powershell
atlas config --suppress-rule python-eval --file app.py --days 30 --reason "revisado"
atlas config --list-suppressions
```

Na TUI do Watchdog, selecione um finding e pressione `X` para abrir o diálogo de
supressão (motivo obrigatório). Findings suprimidos não falham mais um build e
são excluídos dos novos alertas.

## Configuração por projeto

Um repositório pode ajustar o scanner sem alterar as configurações globais
adicionando um arquivo `.atlas.toml` na sua raiz:

```toml
[scan]
ignored_rules = ["python-eval", "B602"]
risk_overrides = { B602 = "LOW" }
```

Substituições por projeto são mescladas com as configurações do usuário e
aplicadas a todo scan (CLI e Watchdog). Arquivos inválidos são ignorados, nunca
fatais.

## Relatórios

Use **4. Generate Report** no launcher (ou ative-o pelo teclado) para gravar um
relatório Markdown local contendo o último Security Score do sistema, findings
do Watchdog, status dos scanners, evidências, risco, recomendações e o histórico
sanitizado de alterações de arquivos de cada projeto conhecido. Sem `--project`,
o relatório consolida todos os projetos configurados e previamente analisados. O
arquivo é salvo na pasta Downloads do Windows como `atlas-report-YYYY-MM-DD.md`;
um relatório existente nunca é sobrescrito e um sufixo de horário é usado quando
necessário. Todos os campos do relatório são sanitizados e valores sensíveis são
substituídos por `[REDACTED]`.

Os relatórios também podem ser gerados diretamente pela CLI:

```powershell
atlas report --format md
atlas report --format html
atlas report --format json
atlas report --format sarif
atlas report --project "C:\Meu Projeto" --output "C:\Relatorios"
```

## TUI do Watchdog

Visões: Overview, Watchdog, New Findings, All Findings, Resolved, Scan e Settings.

Atalhos de teclado:

- `W`: iniciar ou parar o watch
- `S`: executar um scan manual completo
- `Enter`: abrir detalhes do finding selecionado
- `A`: solicitar uma revisão de IA local do finding selecionado quando iniciado com `--ai`
- `R`: atualizar
- `Q`: sair

## Arquivos suportados

O ATLAS registra eventos de criação, modificação, movimentação e exclusão para
todo arquivo não ignorado. Os scans de segurança priorizam `.html`, `.py`, `.js`,
`.ts`, `.tsx`, `.jsx`, `.ps1`, `.bat`, `.json`, `.yaml`, `.yml`, `Dockerfile` e
arquivos Compose. O conteúdo dos arquivos nunca é armazenado no histórico de
atividades.

Ele ignora metadados de VCS, `node_modules`, ambientes virtuais, `site-packages`,
caches do Python, artefatos de teste/build, `dist` e `build`.

## Ciclo de vida de findings

Uma fingerprint SHA-256 estável usa scanner, regra, caminho de arquivo
normalizado relativo ao projeto e uma identidade de contexto sanitizada do
código-fonte. Ela sobrevive a inserções de linhas não relacionadas sem armazenar
código ou valores de segredos. A baseline inicial do Watch é aceita como
EXISTING, de modo que apenas regressões posteriores se tornam NEW. Em cada scan:

- `NEW`: não estava ativo no estado medido anterior ou reapareceu;
- `EXISTING`: ainda presente;
- `RESOLVED`: ausente de um escopo scanner/arquivo que foi medido com sucesso.
- `UNVERIFIED`: o scanner responsável falhou, foi ignorado ou não pôde confirmar cobertura.

Um scanner indisponível não tem cobertura e, portanto, não pode marcar
acidentalmente seus findings antigos como resolvidos.

A confiança é uma heurística de regra/contexto para triagem, não uma
probabilidade calibrada. Scanners ausentes e arquivos-fonte elegíveis acima de
2 MB são mostrados como lacunas de cobertura; eles nunca são descritos como
analisados de forma limpa. Resultados incrementais do Watchdog cobrem
explicitamente apenas arquivos alterados e não são reportados como um scan
completo do projeto. A baseline inicial é aceita uma vez por projeto; inícios
subsequentes do Watchdog ainda reportam findings recém-descobertos.

## Privacidade e segurança

O ATLAS é somente leitura por padrão e nunca explora vulnerabilidades. As
evidências são sanitizadas antes da exibição ou armazenamento. Senhas, tokens,
chaves de API, cookies, strings de conexão, chaves privadas, valores de `.env` e
formatos comuns de credenciais são substituídos por `[REDACTED]` ou omitidos
totalmente.

O Security Guard usa padrões heurísticos nos arquivos-fonte suportados para
sinalizar possíveis sequências de prompt injection, exfiltração e instruções
codificadas. Não é uma garantia semântica de segurança nem um interceptor global
para navegadores, e-mails, ferramentas ou outros agentes. O revisor Ollama
recebe o código-fonte como dado não confiável e não possui ferramentas de
execução; instruções de prompt sozinhas não garantem que um modelo ignorará toda
injeção. Os resultados ainda exigem revisão humana.

Para atividades comuns de arquivos, o ATLAS armazena apenas metadados
sanitizados: timestamp, tipo de evento, severidade e caminho. Ele não armazena o
conteúdo dos arquivos. Nomes de arquivos sensíveis são substituídos por
`[SENSITIVE_FILE]`.

## Limitações

- Windows é a plataforma primária suportada; outros sistemas são best effort.
- A precisão e a cobertura dos scanners opcionais dependem das versões e regras instaladas.
- A configuração `auto` do Semgrep e os bancos de vulnerabilidades podem exigir acesso à rede.
- Verificações protegidas em todo o sistema podem ficar incompletas sem acesso de Administrador; o ATLAS reporta cobertura reduzida em vez de falhar.
- `atlas agent` abre o painel integrado. `--advanced` permanece como alias de compatibilidade. O chat usa Ollama quando disponível; caso contrário, regras locais.
- O scanner nativo é intencionalmente conservador e não substitui scanners especializados nem uma revisão profissional de segurança.
- O Ollama melhora o contexto, mas ainda pode errar; scanners determinísticos permanecem autoritativos e a revisão de IA é claramente rotulada.
- O ATLAS complementa o Microsoft Defender. Não é um motor antimalware e não pode garantir a detecção de todo malware, spyware, rootkit ou ataque zero-day.
- A telemetria do Defender pode exigir acesso de Administrador sob política corporativa; o ATLAS reporta essa limitação em vez de contorná-la.

## Desenvolvimento

```powershell
python -m pytest -q
atlas --version
atlas watch . --once
.\tools\build_windows.ps1
.\release\ATLAS-Security-Agent.exe --version
```

Veja [CHANGELOG.md](CHANGELOG.md) para as notas de release. Detalhes de
contribuição estão em [CONTRIBUTING.md](CONTRIBUTING.md) e o código de conduta
em [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Contribuindo

Contribuições são bem-vindas. Leia [CONTRIBUTING.md](CONTRIBUTING.md) para o
fluxo de desenvolvimento e [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) para as
regras de convivência. Para relatar uma vulnerabilidade, use um GitHub Security
Advisory privado, conforme descrito em [SECURITY.md](SECURITY.md).

## Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE) para mais detalhes.
