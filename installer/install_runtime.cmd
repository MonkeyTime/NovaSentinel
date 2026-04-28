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
  "@{Path=(Join-Path $startup 'NovaSentinel.lnk'); Description='Launch NovaSentinel at sign-in'}," ^
  "@{Path=(Join-Path $programs 'NovaSentinel.lnk'); Description='Open NovaSentinel'}," ^
  "@{Path=(Join-Path $desktop 'NovaSentinel.lnk'); Description='Open NovaSentinel'}" ^
  "); " ^
  "foreach ($item in $targets) { " ^
  "  $shortcut = $shell.CreateShortcut($item.Path); " ^
  "  $shortcut.TargetPath = Join-Path '%DEST%' 'NovaSentinel.exe'; " ^
  "  $shortcut.WorkingDirectory = '%DEST%'; " ^
  "  $shortcut.IconLocation = Join-Path '%DEST%' 'NovaSentinel.exe'; " ^
  "  $shortcut.Description = $item.Description; " ^
  "  $shortcut.Save(); " ^
  "} "
if errorlevel 1 goto :fail

start "" "%DEST%\NovaSentinel.exe"

echo %APP_NAME% installation completed.
exit /b 0

:fail
echo Installation failed.
exit /b 1
