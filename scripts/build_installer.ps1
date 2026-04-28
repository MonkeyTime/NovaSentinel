param(
    [switch]$RebuildApp,
    [string]$OutputName
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DistDir = Join-Path $ProjectRoot "dist\NovaSentinel"
$InstallerDir = Join-Path $ProjectRoot "installer"
$ReleaseDir = Join-Path $ProjectRoot "release"
$StageDir = Join-Path $ReleaseDir "installer_stage"
$ZipPath = Join-Path $StageDir "NovaSentinel.zip"
$SedPath = Join-Path $StageDir "NovaSentinelInstaller.sed"
if ([string]::IsNullOrWhiteSpace($OutputName)) {
    $OutputName = "NovaSentinel-Setup-{0}.exe" -f (Get-Date -Format "yyyyMMdd-HHmmss")
}
$TargetInstaller = Join-Path $ReleaseDir $OutputName

if ($RebuildApp -or -not (Test-Path (Join-Path $DistDir "NovaSentinel.exe"))) {
    powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "build_windows.ps1") -Clean
}

if (-not (Test-Path (Join-Path $DistDir "NovaSentinel.exe"))) {
    throw "Executable not found in $DistDir"
}

Remove-Item $StageDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $TargetInstaller -Force -ErrorAction SilentlyContinue
Get-ChildItem $ReleaseDir -Force -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -like "~NovaSentinel-Setup*.DDF" -or $_.Name -like "~NovaSentinel-Setup*.CAB"
} | Remove-Item -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $StageDir, $ReleaseDir | Out-Null

Compress-Archive -Path (Join-Path $DistDir "*") -DestinationPath $ZipPath -Force
Copy-Item (Join-Path $InstallerDir "install_runtime.cmd") (Join-Path $StageDir "install_runtime.cmd") -Force
Copy-Item (Join-Path $InstallerDir "uninstall_runtime.ps1") (Join-Path $StageDir "uninstall_runtime.ps1") -Force

$sed = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=0
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=
DisplayLicense=
FinishMessage=NovaSentinel installation completed.
TargetName=$TargetInstaller
FriendlyName=NovaSentinel Setup
AppLaunched=install_runtime.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=install_runtime.cmd
UserQuietInstCmd=install_runtime.cmd
SourceFiles=SourceFiles
SelfDelete=0
[SourceFiles]
SourceFiles0=$StageDir
[SourceFiles0]
%FILE0%= 
%FILE1%= 
%FILE2%= 
[Strings]
FILE0=NovaSentinel.zip
FILE1=install_runtime.cmd
FILE2=uninstall_runtime.ps1
"@

Set-Content -LiteralPath $SedPath -Value $sed -Encoding ASCII

& "$env:SystemRoot\System32\iexpress.exe" /N $SedPath
$installerBuilt = Test-Path $TargetInstaller

if (-not $installerBuilt) {
    throw "Installer was not created."
}

Write-Host "Installer created at $TargetInstaller"
exit 0
