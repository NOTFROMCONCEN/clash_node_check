[CmdletBinding()]
param(
    [string]$Version
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Command
    )

    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Get-CargoVersion {
    $match = Select-String -Path 'Cargo.toml' -Pattern '^version\s*=\s*"([^"]+)"$'
    if (-not $match) {
        throw 'Failed to read version from Cargo.toml.'
    }

    return $match.Matches[0].Groups[1].Value
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-CargoVersion
}

$bundleName = "clash-node-checker-v$Version-windows-x86_64"
$distDir = Join-Path $repoRoot 'dist'
$bundleDir = Join-Path $distDir $bundleName
$releaseExe = Join-Path $repoRoot 'target\release\clash-node-checker.exe'
$exeAsset = Join-Path $distDir ($bundleName + '.exe')
$zipAsset = Join-Path $distDir ($bundleName + '.zip')
$hashAsset = Join-Path $distDir ($bundleName + '.sha256.txt')

Invoke-NativeCommand -Description 'sanitize preflight' -Command {
    & (Join-Path $PSScriptRoot 'preflight-sanitize.ps1')
}
Invoke-NativeCommand -Description 'cargo test' -Command {
    cargo test
}
Invoke-NativeCommand -Description 'cargo build --release' -Command {
    cargo build --release
}

if (-not (Test-Path $releaseExe)) {
    throw "Release executable not found: $releaseExe"
}

New-Item -ItemType Directory -Path $distDir -Force | Out-Null
Remove-Item $bundleDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $exeAsset, $zipAsset, $hashAsset -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Path $bundleDir -Force | Out-Null
Copy-Item $releaseExe (Join-Path $bundleDir 'clash-node-checker.exe') -Force
Copy-Item 'README.md' (Join-Path $bundleDir 'README.md') -Force
Copy-Item $releaseExe $exeAsset -Force

Compress-Archive -Path (Join-Path $bundleDir '*') -DestinationPath $zipAsset -Force

$hash = Get-FileHash -Path $zipAsset -Algorithm SHA256
('{0}  {1}' -f $hash.Hash, (Split-Path $zipAsset -Leaf)) | Set-Content -Path $hashAsset -NoNewline

Write-Host "Build complete: $exeAsset" -ForegroundColor Green
Write-Host "Archive complete: $zipAsset" -ForegroundColor Green
Write-Host "Checksum file: $hashAsset" -ForegroundColor Green