param(
    [string]$Version = "",
    [string]$OutputPath = "",
    [switch]$IncludeEmbeddedNode
)

$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$ProjectRoot = Split-Path -Parent $Root
$ConsoleDir = Join-Path $ProjectRoot "admin_console"
$ReleaseDir = Join-Path $ProjectRoot "release"
if (-not (Test-Path $ReleaseDir)) {
    New-Item -ItemType Directory -Path $ReleaseDir | Out-Null
}

$packageJsonPath = Join-Path $ConsoleDir "package.json"
if (-not (Test-Path $packageJsonPath)) {
    throw "admin_console/package.json not found"
}

$package = Get-Content $packageJsonPath -Raw | ConvertFrom-Json
if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = $package.version
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$artifact = "novasentinel-admin-console-v$Version-$timestamp.zip"
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ReleaseDir $artifact
}

$staging = Join-Path $env:TEMP ("novasentinel-admin-console-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $staging | Out-Null
$adminPackageDir = Join-Path $staging "admin_console"
New-Item -ItemType Directory -Path $adminPackageDir | Out-Null

try {
    Copy-Item -Path (Join-Path $ConsoleDir "README.md") -Destination $adminPackageDir -Force
    Copy-Item -Path (Join-Path $ConsoleDir "index.html") -Destination $adminPackageDir -Force
    Copy-Item -Path (Join-Path $ConsoleDir "package.json") -Destination $adminPackageDir -Force
    Copy-Item -Path (Join-Path $ConsoleDir "server.js") -Destination $adminPackageDir -Force
    Copy-Item -Path (Join-Path $ConsoleDir ".env.example") -Destination $adminPackageDir -Force

    Copy-Item -Path (Join-Path $ConsoleDir "src") -Destination $adminPackageDir -Recurse -Force
    Copy-Item -Path (Join-Path $ConsoleDir "tools") -Destination $adminPackageDir -Recurse -Force

    if ($IncludeEmbeddedNode) {
        $NodeRoot = Join-Path $ConsoleDir "node"
        if (Test-Path $NodeRoot) {
            Copy-Item -Path $NodeRoot -Destination $adminPackageDir -Recurse -Force
        } else {
            Write-Warning "IncludeEmbeddedNode requested but admin_console/node not found. Continuing without embedded runtime."
        }
    }

    Compress-Archive -Path $adminPackageDir -DestinationPath $OutputPath -CompressionLevel Optimal -Force
    Write-Host "Admin Console package created: $OutputPath"
} finally {
    Remove-Item -Recurse -Force $staging -ErrorAction SilentlyContinue
}
