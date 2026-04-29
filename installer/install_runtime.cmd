@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "APP_NAME=NovaSentinel"
set "DEST=%LOCALAPPDATA%\Programs\%APP_NAME%"
set "ZIP_PATH=%SCRIPT_DIR%NovaSentinel.zip"
set "UNINSTALL_SOURCE=%SCRIPT_DIR%uninstall_runtime.ps1"

echo Installing %APP_NAME% to "%DEST%"

taskkill /IM NovaSentinel.exe /F >nul 2>nul
if exist "%DEST%" rmdir /S /Q "%DEST%"
mkdir "%DEST%"

powershell -NoProfile -ExecutionPolicy Bypass -Command "Expand-Archive -LiteralPath '%ZIP_PATH%' -DestinationPath '%DEST%' -Force"
if errorlevel 1 goto :fail

copy /Y "%UNINSTALL_SOURCE%" "%DEST%\uninstall_runtime.ps1" >nul

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$shell = New-Object -ComObject WScript.Shell; " ^
  "$startup = [Environment]::GetFolderPath('Startup'); " ^
  "$programs = [Environment]::GetFolderPath('Programs'); " ^
  "$desktop = [Environment]::GetFolderPath('Desktop'); " ^
  "$targets = @(" ^
  "@{Path=(Join-Path $startup 'NovaSentinel.lnk'); Description='Launch NovaSentinel at sign-in'; Arguments='--background'}," ^
  "@{Path=(Join-Path $programs 'NovaSentinel.lnk'); Description='Open NovaSentinel'; Arguments=''}," ^
  "@{Path=(Join-Path $desktop 'NovaSentinel.lnk'); Description='Open NovaSentinel'; Arguments=''}" ^
  "); " ^
  "foreach ($item in $targets) { " ^
  "  $shortcut = $shell.CreateShortcut($item.Path); " ^
  "  $shortcut.TargetPath = Join-Path '%DEST%' 'NovaSentinel.exe'; " ^
  "  $shortcut.Arguments = $item.Arguments; " ^
  "  $shortcut.WorkingDirectory = '%DEST%'; " ^
  "  $shortcut.IconLocation = Join-Path '%DEST%' 'NovaSentinel.exe'; " ^
  "  $shortcut.Description = $item.Description; " ^
  "  $shortcut.Save(); " ^
  "} "
if errorlevel 1 goto :fail

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$action = New-ScheduledTaskAction -Execute (Join-Path '%DEST%' 'NovaSentinel.exe') -Argument '--background'; " ^
  "$trigger = New-ScheduledTaskTrigger -AtLogOn; " ^
  "$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; " ^
  "$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest; " ^
  "$settings = New-ScheduledTaskSettingsSet; " ^
  "Register-ScheduledTask -TaskName '%APP_NAME%' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null" >nul 2>nul
if not errorlevel 1 (
  del "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\NovaSentinel.lnk" >nul 2>nul
)

start "" "%DEST%\NovaSentinel.exe"

echo %APP_NAME% installation completed.
exit /b 0

:fail
echo Installation failed.
exit /b 1
