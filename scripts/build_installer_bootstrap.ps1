param(
    [switch]$RebuildApp,
    [string]$OutputName
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DistDir = Join-Path $ProjectRoot "dist\NovaSentinel"
$ReleaseDir = Join-Path $ProjectRoot "release"
$StageDir = Join-Path $ReleaseDir "installer_stage_bootstrap"
$ZipPath = Join-Path $StageDir "NovaSentinel.zip"
$VenvPath = Join-Path $ProjectRoot ".venv"
$Python = Join-Path $VenvPath "Scripts\python.exe"
$IconPath = Join-Path $ProjectRoot "installer\\novasentinel_icon.ico"

if ([string]::IsNullOrWhiteSpace($OutputName)) {
    $OutputName = "NovaSentinel-Setup-{0}.exe" -f (Get-Date -Format "yyyyMMdd-HHmmss")
}

if ($RebuildApp -or -not (Test-Path (Join-Path $DistDir "NovaSentinel.exe"))) {
    powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build_windows.ps1") -Clean
}

if (-not (Test-Path (Join-Path $DistDir "NovaSentinel.exe"))) {
    throw "Executable not found in $DistDir"
}

New-Item -ItemType Directory -Force -Path $StageDir, $ReleaseDir | Out-Null
Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $DistDir "*") -DestinationPath $ZipPath -Force

& $Python -m pip install pyinstaller
@"
from pathlib import Path
from novaguard.bootstrap import ensure_icon_assets

project_root = Path(r"$ProjectRoot")
ensure_icon_assets(project_root / "installer", force=True)
"@ | & $Python -

$OutputPath = Join-Path $ReleaseDir $OutputName
Remove-Item $OutputPath -Force -ErrorAction SilentlyContinue
$UninstallData = "$(Join-Path $ProjectRoot 'installer\uninstall_runtime.ps1');."

& $Python -m PyInstaller `
    --noconfirm `
    --onefile `
    --windowed `
    --uac-admin `
    --name ([System.IO.Path]::GetFileNameWithoutExtension($OutputName)) `
    --icon $IconPath `
    --distpath $ReleaseDir `
    --workpath (Join-Path $ProjectRoot "build\installer_bootstrap") `
    --specpath $ProjectRoot `
    --add-data "$ZipPath;." `
    --add-data $UninstallData `
    (Join-Path $ProjectRoot "installer\bootstrap_installer.py")

if (-not (Test-Path $OutputPath)) {
    throw "Bootstrap installer was not created."
}

Write-Host "Installer created at $OutputPath"
