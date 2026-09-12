$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Icon = Join-Path $ProjectRoot "src\atlas\assets\atlas.ico"
$VersionInfo = Join-Path $ProjectRoot "tools\windows_version_info.txt"
$Release = Join-Path $ProjectRoot "release"

Set-Location $ProjectRoot
python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --console `
    --name "ATLAS-Security-Agent" `
    --icon $Icon `
    --version-file $VersionInfo `
    --add-data "src\atlas\assets;atlas\assets" `
    --add-data "src\atlas\rules;atlas\rules" `
    --collect-all textual `
    --distpath $Release `
    src\atlas\__main__.py

Write-Host "ATLAS criado em $Release\ATLAS-Security-Agent.exe"
