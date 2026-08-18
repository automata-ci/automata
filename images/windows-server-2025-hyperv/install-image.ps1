[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $ExpectedSourceCommit,
    [Parameter(Mandatory = $true)][ValidateRange(1, 8589934591)][int64] $ExpectedSourceDateEpoch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-Sha256 {
    param(
        [Parameter(Mandatory = $true)][string] $Path,
        [Parameter(Mandatory = $true)][string] $Expected
    )

    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($actual -cne $Expected) {
        throw "artifact SHA-256 differs: $Path"
    }
}

function Assert-ExactKeys {
    param(
        [Parameter(Mandatory = $true)] $Value,
        [Parameter(Mandatory = $true)][string[]] $Expected,
        [Parameter(Mandatory = $true)][string] $Label
    )

    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expectedSorted = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($expectedSorted -join "`n")) {
        throw "$Label keys differ"
    }
}

$buildRoot = 'C:\automata\build'
$sourceLockPath = Join-Path $buildRoot 'sources.lock.json'
$inputLockPath = Join-Path $buildRoot 'build-inputs.json'
$sourceLock = Get-Content -Raw -LiteralPath $sourceLockPath | ConvertFrom-Json
$inputLock = Get-Content -Raw -LiteralPath $inputLockPath | ConvertFrom-Json

Assert-ExactKeys $sourceLock @(
    'architecture', 'base_image', 'profile_id', 'schema_version', 'sources', 'variant'
) 'source lock'
Assert-ExactKeys $inputLock @(
    'containerfile_sha256', 'guest_agent', 'hash_helper', 'install_script_sha256',
    'schema_version', 'source_commit', 'source_date_epoch', 'source_lock_sha256'
) 'build input lock'

if ($sourceLock.schema_version -ne 1 -or $inputLock.schema_version -ne 1) {
    throw 'unsupported image input schema'
}
if ($inputLock.source_commit -cne $ExpectedSourceCommit `
    -or [int64]$inputLock.source_date_epoch -ne $ExpectedSourceDateEpoch) {
    throw 'source identity differs from the immutable build arguments'
}
Assert-Sha256 $sourceLockPath $inputLock.source_lock_sha256
Assert-Sha256 (Join-Path $buildRoot 'Containerfile') $inputLock.containerfile_sha256
Assert-Sha256 (Join-Path $buildRoot 'install-image.ps1') $inputLock.install_script_sha256

$expectedKinds = @('pwsh', 'node24')
$actualKinds = @($sourceLock.sources | ForEach-Object { $_.kind })
if (($actualKinds -join "`n") -cne ($expectedKinds -join "`n")) {
    throw 'source lock artifact order differs'
}
foreach ($source in $sourceLock.sources) {
    Assert-ExactKeys $source @('filename', 'kind', 'sha256', 'url', 'version') 'source'
    Assert-Sha256 (Join-Path $buildRoot $source.filename) $source.sha256
}

foreach ($local in @($inputLock.guest_agent, $inputLock.hash_helper)) {
    Assert-ExactKeys $local @('filename', 'sha256') 'local artifact'
    Assert-Sha256 (Join-Path $buildRoot $local.filename) $local.sha256
}

$powerShellRoot = 'C:\Program Files\PowerShell\7'
$nodeRoot = 'C:\automata\externals\node24'
$hashRoot = 'C:\automata\tools\hash'
$guestRoot = 'C:\automata\guest'
$temporaryRoot = 'C:\automata\temp'
$workspaceRoot = 'C:\__w'
New-Item -ItemType Directory -Force -Path @(
    $powerShellRoot, $nodeRoot, $hashRoot, $guestRoot,
    $temporaryRoot, $workspaceRoot, 'C:\automata\home', 'C:\automata\toolcache'
) | Out-Null

Expand-Archive -LiteralPath (Join-Path $buildRoot 'PowerShell-7.6.5-win-x64.zip') `
    -DestinationPath $powerShellRoot

$nodeStage = Join-Path $buildRoot 'node-stage'
Expand-Archive -LiteralPath (Join-Path $buildRoot 'node-v24.19.0-win-x64.zip') `
    -DestinationPath $nodeStage
$nodeSource = Join-Path $nodeStage 'node-v24.19.0-win-x64'
Copy-Item -Path (Join-Path $nodeSource '*') -Destination $nodeRoot -Recurse -Force

Copy-Item -LiteralPath (Join-Path $buildRoot $inputLock.hash_helper.filename) `
    -Destination (Join-Path $hashRoot 'automata-sha256.exe')
Copy-Item -LiteralPath (Join-Path $buildRoot $inputLock.guest_agent.filename) `
    -Destination (Join-Path $guestRoot 'automata-ci-sandbox-guest.exe')

$expectedPrograms = @(
    (Join-Path $powerShellRoot 'pwsh.exe'),
    (Join-Path $nodeRoot 'node.exe'),
    (Join-Path $hashRoot 'automata-sha256.exe'),
    (Join-Path $guestRoot 'automata-ci-sandbox-guest.exe')
)
foreach ($program in $expectedPrograms) {
    if (-not (Test-Path -LiteralPath $program -PathType Leaf)) {
        throw "installed image tool is absent: $program"
    }
}

$hashVersion = & (Join-Path $hashRoot 'automata-sha256.exe') --version
$nodeVersion = & (Join-Path $nodeRoot 'node.exe') --version
$pwshVersion = & (Join-Path $powerShellRoot 'pwsh.exe') -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
if (-not $hashVersion.StartsWith('automata-sha256 ') `
    -or $nodeVersion -cne 'v24.19.0' `
    -or $pwshVersion -cne '7.6.5') {
    throw 'installed image tool version differs from the source lock'
}

foreach ($root in @(
    'C:\automata', $powerShellRoot, 'C:\automata\externals',
    'C:\automata\tools', $guestRoot
)) {
    & icacls.exe $root /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "could not remove inherited image ACL: $root"
    }
    & icacls.exe $root /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
        '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "could not seal image ACL: $root"
    }
}
foreach ($root in @(
    $workspaceRoot, $temporaryRoot, 'C:\automata\home', 'C:\automata\toolcache'
)) {
    & icacls.exe $root /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "could not remove inherited image ACL: $root"
    }
    & icacls.exe $root /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
        '*S-1-5-93-2-1:(OI)(CI)M' | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "could not configure writable image root: $root"
    }
}
$sourceTimestamp = [DateTimeOffset]::FromUnixTimeSeconds([int64]$inputLock.source_date_epoch).UtcDateTime
foreach ($root in @($powerShellRoot, 'C:\automata', $workspaceRoot)) {
    Get-ChildItem -LiteralPath $root -Recurse -Force | ForEach-Object {
        $_.CreationTimeUtc = $sourceTimestamp
        $_.LastAccessTimeUtc = $sourceTimestamp
        $_.LastWriteTimeUtc = $sourceTimestamp
    }
    (Get-Item -LiteralPath $root).CreationTimeUtc = $sourceTimestamp
    (Get-Item -LiteralPath $root).LastAccessTimeUtc = $sourceTimestamp
    (Get-Item -LiteralPath $root).LastWriteTimeUtc = $sourceTimestamp
}
