param(
    [switch]$KeepData
)

$ErrorActionPreference = "SilentlyContinue"
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$StartupShortcut = Join-Path ([Environment]::GetFolderPath("Startup")) "NovaSentinel.lnk"
$ProgramsShortcut = Join-Path ([Environment]::GetFolderPath("Programs")) "NovaSentinel.lnk"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "NovaSentinel.lnk"

Get-Process NovaSentinel -ErrorAction SilentlyContinue | Stop-Process -Force

Remove-Item $StartupShortcut -Force
Remove-Item $ProgramsShortcut -Force
Remove-Item $DesktopShortcut -Force

if (-not $KeepData) {
    $AppDataState = Join-Path $env:APPDATA "NovaSentinel"
    Remove-Item $AppDataState -Recurse -Force
}

Start-Sleep -Milliseconds 300
Remove-Item $InstallDir -Recurse -Force
