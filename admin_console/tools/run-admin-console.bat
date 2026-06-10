@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
set "APP_DIR=%SCRIPT_DIR%\.."
pushd "%APP_DIR%" >nul

if exist ".env" (
  for /f "usebackq delims=" %%L in (".env") do (
    set "line=%%L"
    if defined line (
      set "line=!line:~0,255!"
      if not "!line:~0,1!"=="#" (
        for /f "tokens=1,* delims==" %%A in ("!line!") do (
          if not "%%A"=="" (
            set "%%A=%%B"
          )
        )
      )
    )
  )
)

set "NODE_EXE=%NOVASENTINEL_NODE_BIN%"
if defined NODE_EXE if not exist "%NODE_EXE%" (
  echo NOVASENTINEL_NODE_BIN is set but invalid: %NODE_EXE%
  popd >nul
  exit /b 1
)

if not defined NODE_EXE (
  if exist "%APP_DIR%\node\node.exe" (
    set "NODE_EXE=%APP_DIR%\node\node.exe"
  ) else if exist "%APP_DIR%\node\bin\node.exe" (
    set "NODE_EXE=%APP_DIR%\node\bin\node.exe"
  ) else (
    where node >nul 2>&1
    if errorlevel 1 (
      echo Node.js not found. Install Node.js or place it at node\node.exe.
      popd >nul
      exit /b 1
    )
    for /f "delims=" %%P in ('where node') do (
      set "NODE_EXE=%%P"
      goto :nodeFound
    )
  )
)

:nodeFound
if not defined NODE_EXE (
  echo Node.js not found. Install Node.js or place it at node\node.exe.
  popd >nul
  exit /b 1
)

if not defined NOVASENTINEL_ADMIN_HOST set "NOVASENTINEL_ADMIN_HOST=127.0.0.1"
if not defined NOVASENTINEL_ADMIN_PORT set "NOVASENTINEL_ADMIN_PORT=8790"
if not defined NODE_ENV set "NODE_ENV=production"

echo NovaSentinel Admin Console starting on http://%NOVASENTINEL_ADMIN_HOST%:%NOVASENTINEL_ADMIN_PORT%
echo Node: %NODE_EXE%
"%NODE_EXE%" server.js
set "EXIT_CODE=%errorlevel%"
popd >nul
exit /b %EXIT_CODE%
