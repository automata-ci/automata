[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $SourceCommit,
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [string] $Cargo = 'cargo',
    [string] $Git = 'git'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $scriptRoot '..\..')).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
$targetRoot = Join-Path $repositoryRoot 'target\windows-image-tool-build'
$firstTarget = Join-Path $targetRoot 'first'
$secondTarget = Join-Path $targetRoot 'second'

if ($SourceCommit -ceq ('0' * 40)) {
    throw 'source commit must not be a placeholder'
}
& $Git -C $repositoryRoot cat-file -e "$SourceCommit^{commit}"
if ($LASTEXITCODE -ne 0) {
    throw 'source commit is not present in the repository'
}
$head = (& $Git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -cne $SourceCommit) {
    throw 'source checkout HEAD differs from the requested commit'
}
$status = @(& $Git -C $repositoryRoot status --porcelain=v1 --untracked-files=all)
if ($LASTEXITCODE -ne 0 -or $status.Count -ne 0) {
    throw 'source checkout must be completely clean before building image helpers'
}
if (Test-Path -LiteralPath $output) {
    throw 'refusing to overwrite local image artifacts'
}
$resolvedTargetRoot = [IO.Path]::GetFullPath($targetRoot)
$resolvedRepositoryTarget = [IO.Path]::GetFullPath((Join-Path $repositoryRoot 'target'))
if (-not $resolvedTargetRoot.StartsWith($resolvedRepositoryTarget + [IO.Path]::DirectorySeparatorChar)) {
    throw 'tool build scratch escaped the repository target directory'
}

$sourceEpoch = (& $Git -C $repositoryRoot show -s --format=%ct $SourceCommit).Trim()
if ($LASTEXITCODE -ne 0 -or $sourceEpoch -notmatch '^[1-9][0-9]*$') {
    throw 'could not derive the source commit timestamp'
}

$savedRustFlags = $env:RUSTFLAGS
$savedIncremental = $env:CARGO_INCREMENTAL
$savedEpoch = $env:SOURCE_DATE_EPOCH
$completed = $false
try {
    $env:RUSTFLAGS = "--remap-path-prefix=$repositoryRoot=. -C link-arg=/Brepro -C strip=symbols"
    $env:CARGO_INCREMENTAL = '0'
    $env:SOURCE_DATE_EPOCH = $sourceEpoch
    foreach ($target in @($firstTarget, $secondTarget)) {
        & $Cargo build `
            --locked `
            --release `
            --target x86_64-pc-windows-msvc `
            --target-dir $target `
            --package automata-ci-sandbox-guest `
            --bins
        if ($LASTEXITCODE -ne 0) {
            throw 'could not build Windows image helper artifacts'
        }
    }

    $relative = 'x86_64-pc-windows-msvc\release'
    $artifacts = @('automata-ci-sandbox-guest.exe', 'automata-sha256.exe')
    foreach ($artifact in $artifacts) {
        $first = Join-Path (Join-Path $firstTarget $relative) $artifact
        $second = Join-Path (Join-Path $secondTarget $relative) $artifact
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $first).Hash `
            -cne (Get-FileHash -Algorithm SHA256 -LiteralPath $second).Hash) {
            throw "Windows image helper is not reproducible: $artifact"
        }
    }

    New-Item -ItemType Directory -Path $output | Out-Null
    foreach ($artifact in $artifacts) {
        Copy-Item -LiteralPath (Join-Path (Join-Path $firstTarget $relative) $artifact) `
            -Destination (Join-Path $output $artifact)
        $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $output $artifact)).Hash.ToLowerInvariant()
        Write-Output "$artifact=$hash"
    }
    $completed = $true
}
finally {
    $env:RUSTFLAGS = $savedRustFlags
    $env:CARGO_INCREMENTAL = $savedIncremental
    $env:SOURCE_DATE_EPOCH = $savedEpoch
    foreach ($target in @($firstTarget, $secondTarget)) {
        if (Test-Path -LiteralPath $target) {
            Remove-Item -LiteralPath $target -Recurse -Force
        }
    }
    if (-not $completed -and (Test-Path -LiteralPath $output)) {
        Remove-Item -LiteralPath $output -Recurse -Force
    }
}
