[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $repoRoot

function Get-WorkspaceFiles {
    Get-ChildItem -Path $repoRoot -Recurse -File | Where-Object {
        $_.FullName -notlike '*\.git\*' -and
        $_.FullName -notlike '*\target\*' -and
        $_.FullName -notlike '*\dist\*'
    }
}

function Find-MatchFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Pattern
    )

    $rg = Get-Command rg -ErrorAction SilentlyContinue
    if ($rg) {
        $rgCommonArgs = @(
            '--hidden'
            '--glob'
            '!.git/**'
            '--glob'
            '!target/**'
            '--glob'
            '!dist/**'
        )

        $files = & rg -l --pcre2 @rgCommonArgs $Pattern .
        if ($LASTEXITCODE -gt 1) {
            throw "sanitize scan failed with ripgrep exit code $LASTEXITCODE."
        }

        if ($LASTEXITCODE -eq 0 -and $files) {
            return @($files)
        }

        return @()
    }

    $matches = Get-WorkspaceFiles | Select-String -Pattern $Pattern -AllMatches -ErrorAction SilentlyContinue
    if (-not $matches) {
        return @()
    }

    return @($matches | Select-Object -ExpandProperty Path -Unique)
}

$checks = @(
    @{ Name = 'GitHub token'; Pattern = 'ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}' },
    @{ Name = 'Private key'; Pattern = '-----BEGIN (RSA|DSA|EC|OPENSSH|PGP|PRIVATE) KEY-----' },
    @{ Name = 'Authorization header'; Pattern = 'Authorization:\s*(Bearer|token)\s+[A-Za-z0-9._-]+' },
    @{ Name = 'Credential URL parameter'; Pattern = 'https?://\S+[?&](token|secret|auth|key|password)=' }
)

$hits = @()
foreach ($check in $checks) {
    $files = @(Find-MatchFiles -Pattern $check.Pattern)
    if ($files.Count -gt 0) {
        $hits += [PSCustomObject]@{
            Name  = $check.Name
            Files = @($files)
        }
    }
}

if ($hits.Count -gt 0) {
    Write-Host 'Potential sensitive material detected:' -ForegroundColor Yellow
    foreach ($hit in $hits) {
        Write-Host ("- {0}: {1}" -f $hit.Name, ($hit.Files -join ', ')) -ForegroundColor Yellow
    }
    throw 'Sanitize preflight failed. Remove or mask the files above before publishing.'
}

Write-Host 'Sanitize preflight passed. No obvious tokens or private keys were found.' -ForegroundColor Green

