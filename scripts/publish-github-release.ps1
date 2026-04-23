[CmdletBinding()]
param(
    [string]$Version,
    [string]$RepositoryUrl = 'https://github.com/NOTFROMCONCEN/clash_node_check.git',
    [string]$RepositorySlug = 'NOTFROMCONCEN/clash_node_check',
    [switch]$SkipBuild,
    [switch]$SkipSanitize
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

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'GitHub CLI (gh) is required to publish releases.'
}

Invoke-NativeCommand -Description 'gh auth status' -Command {
    gh auth status
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-CargoVersion
}

$tag = "v$Version"
$bundleName = "clash-node-checker-v$Version-windows-x86_64"
$distDir = Join-Path $repoRoot 'dist'
$exeAsset = Join-Path $distDir ($bundleName + '.exe')
$zipAsset = Join-Path $distDir ($bundleName + '.zip')
$hashAsset = Join-Path $distDir ($bundleName + '.sha256.txt')
$releaseNotesPath = Join-Path $repoRoot (Join-Path 'release-notes' ($tag + '.md'))

if (-not $SkipSanitize) {
    Invoke-NativeCommand -Description 'sanitize preflight' -Command {
        & (Join-Path $PSScriptRoot 'preflight-sanitize.ps1')
    }
}

if (-not $SkipBuild) {
    Invoke-NativeCommand -Description 'build release assets' -Command {
        & (Join-Path $PSScriptRoot 'build-release.ps1') -Version $Version
    }
}

foreach ($asset in @($exeAsset, $zipAsset, $hashAsset, $releaseNotesPath)) {
    if (-not (Test-Path $asset)) {
        throw "Required release asset not found: $asset"
    }
}

$originUrl = ''
& git remote get-url origin *> $null
if ($LASTEXITCODE -eq 0) {
    $originUrl = (git remote get-url origin).Trim()
}

if ([string]::IsNullOrWhiteSpace($originUrl)) {
    Invoke-NativeCommand -Description 'git remote add origin' -Command {
        git remote add origin $RepositoryUrl
    }
}
elseif ($originUrl -ne $RepositoryUrl) {
    Invoke-NativeCommand -Description 'git remote set-url origin' -Command {
        git remote set-url origin $RepositoryUrl
    }
}

Invoke-NativeCommand -Description 'switch branch to main' -Command {
    git branch -M main
}
Invoke-NativeCommand -Description 'stage release files' -Command {
    git add -A
}

& git diff --cached --quiet --exit-code
if ($LASTEXITCODE -eq 1) {
    Invoke-NativeCommand -Description 'create release commit' -Command {
        git commit -m "release: $tag"
    }
}
elseif ($LASTEXITCODE -gt 1) {
    throw 'Failed to inspect staged changes.'
}

& git rev-parse -q --verify "refs/tags/$tag" *> $null
if ($LASTEXITCODE -eq 0) {
    throw "Tag $tag already exists locally. Remove it or publish a new version."
}

Invoke-NativeCommand -Description "create tag $tag" -Command {
    git tag $tag
}
Invoke-NativeCommand -Description 'push branch main' -Command {
    git push -u origin main
}
Invoke-NativeCommand -Description "push tag $tag" -Command {
    git push origin $tag
}

& gh release view $tag --repo $RepositorySlug *> $null
if ($LASTEXITCODE -eq 0) {
    throw "GitHub release $tag already exists."
}

Invoke-NativeCommand -Description "create GitHub release $tag" -Command {
    gh release create $tag $zipAsset $exeAsset $hashAsset --repo $RepositorySlug --title $tag --notes-file $releaseNotesPath
}

$releaseUrl = "https://github.com/$RepositorySlug/releases/tag/$tag"
Write-Host "Published $tag to $RepositorySlug" -ForegroundColor Green
Write-Host "Release URL: $releaseUrl" -ForegroundColor Green