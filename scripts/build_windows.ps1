param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot ".venv"

if (-not (Test-Path $VenvPath)) {
    py -3 -m venv $VenvPath
}

$Python = Join-Path $VenvPath "Scripts\\python.exe"
$IconPath = Join-Path $ProjectRoot "installer\\novasentinel_icon.ico"

& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $ProjectRoot "requirements.txt")
& $Python -m pip install pyinstaller
@"
from pathlib import Path
from novaguard.bootstrap import ensure_icon_assets

project_root = Path(r"$ProjectRoot")
ensure_icon_assets(project_root / "installer", force=True)
"@ | & $Python -

if ($Clean) {
    Remove-Item -Recurse -Force (Join-Path $ProjectRoot "build") -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force (Join-Path $ProjectRoot "dist") -ErrorAction SilentlyContinue
}

& $Python -m PyInstaller `
    --noconfirm `
    --windowed `
    --uac-admin `
    --name NovaSentinel `
    --icon $IconPath `
    --collect-all customtkinter `
    (Join-Path $ProjectRoot "launch_novaguard.pyw")

$DistDir = Join-Path $ProjectRoot "dist\NovaSentinel"
if (Test-Path $DistDir) {
    Copy-Item -Force $IconPath (Join-Path $DistDir "novasentinel_icon.ico")
}
