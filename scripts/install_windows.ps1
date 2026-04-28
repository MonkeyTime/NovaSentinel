param(
    [switch]$RunNow
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot ".venv"

if (-not (Test-Path $VenvPath)) {
    py -3 -m venv $VenvPath
}

$Python = Join-Path $VenvPath "Scripts\\python.exe"
$PythonW = Join-Path $VenvPath "Scripts\\pythonw.exe"

& $Python -m pip install --upgrade pip
& $Python -m pip install -r (Join-Path $ProjectRoot "requirements.txt")

$StartupDir = [Environment]::GetFolderPath("Startup")
$ShortcutPath = Join-Path $StartupDir "NovaSentinel.lnk"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $PythonW
$Shortcut.Arguments = "`"$($ProjectRoot)\\launch_novaguard.pyw`" --background"
$Shortcut.WorkingDirectory = $ProjectRoot
$Shortcut.IconLocation = Join-Path $env:APPDATA "NovaSentinel\\novasentinel_icon.ico"
$Shortcut.Save()

Write-Host "NovaSentinel installed. Startup shortcut created at $ShortcutPath"

if ($RunNow) {
    Start-Process -FilePath $PythonW -ArgumentList "`"$($ProjectRoot)\\launch_novaguard.pyw`"" -WorkingDirectory $ProjectRoot
}
