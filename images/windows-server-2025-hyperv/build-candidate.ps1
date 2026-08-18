[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $GuestAgent,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string] $GuestAgentSha256,
    [Parameter(Mandatory = $true)][string] $HashHelper,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string] $HashHelperSha256,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string] $SourceCommit,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9._/:-]{2,127}$')][string] $LocalTag,
    [string] $Python = 'python',
    [string] $Docker = 'docker'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $scriptRoot '..\..')).Path
$pipeline = Join-Path $repositoryRoot 'scripts\ci\windows-image-pipeline.py'
$sourceLock = Join-Path $scriptRoot 'sources.lock.json'
$sourceLockSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceLock).Hash.ToLowerInvariant()

if ($SourceCommit -ceq ('0' * 40)) {
    throw 'source commit must not be a placeholder'
}
if ($LocalTag.Contains('@') -or -not $LocalTag.Contains(':')) {
    throw 'local image output must be an explicit non-digest tag'
}
foreach ($path in @($GuestAgent, $HashHelper)) {
    $resolved = Resolve-Path -LiteralPath $path
    if ((Get-Item -LiteralPath $resolved).PSIsContainer) {
        throw "local image artifact is not a regular file: $path"
    }
}
if ((Get-FileHash -Algorithm SHA256 -LiteralPath $GuestAgent).Hash.ToLowerInvariant() -cne $GuestAgentSha256 `
    -or (Get-FileHash -Algorithm SHA256 -LiteralPath $HashHelper).Hash.ToLowerInvariant() -cne $HashHelperSha256) {
    throw 'local image artifact digest differs from its reviewed pin'
}

$targetRoot = Join-Path $repositoryRoot 'target\windows-server-2025-image'
New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null
$context = Join-Path $targetRoot ([Guid]::NewGuid().ToString('N'))

try {
    & $Python $pipeline prepare-context `
        --lock $sourceLock `
        --recipe-directory $scriptRoot `
        --source-tree $repositoryRoot `
        --guest-agent $GuestAgent `
        --guest-agent-sha256 $GuestAgentSha256 `
        --hash-helper $HashHelper `
        --hash-helper-sha256 $HashHelperSha256 `
        --source-commit $SourceCommit `
        --output $context
    if ($LASTEXITCODE -ne 0) {
        throw 'could not prepare the verified image build context'
    }

    $retainedBuildInputs = Join-Path $targetRoot "$SourceCommit.build-inputs.json"
    if (Test-Path -LiteralPath $retainedBuildInputs) {
        $existing = (Get-FileHash -Algorithm SHA256 -LiteralPath $retainedBuildInputs).Hash
        $prepared = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $context 'build-inputs.json')).Hash
        if ($existing -cne $prepared) {
            throw 'retained build inputs differ for the same source commit'
        }
    }
    else {
        Copy-Item -LiteralPath (Join-Path $context 'build-inputs.json') -Destination $retainedBuildInputs
    }
    $buildInputsPath = Join-Path $context 'build-inputs.json'
    $buildInputsSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $buildInputsPath).Hash.ToLowerInvariant()
    $buildInputs = Get-Content -Raw -LiteralPath $buildInputsPath | ConvertFrom-Json
    if ($buildInputs.source_commit -cne $SourceCommit `
        -or [int64]$buildInputs.source_date_epoch -le 0) {
        throw 'prepared build inputs differ from the requested source identity'
    }

    & $Docker build `
        --file (Join-Path $context 'Containerfile') `
        --isolation hyperv `
        --no-cache `
        --pull=false `
        --build-arg "AUTOMATA_BUILD_INPUTS_SHA256=$buildInputsSha256" `
        --build-arg "AUTOMATA_SOURCE_COMMIT=$SourceCommit" `
        --build-arg "AUTOMATA_SOURCE_LOCK_SHA256=$sourceLockSha256" `
        --build-arg "SOURCE_DATE_EPOCH=$($buildInputs.source_date_epoch)" `
        --tag $LocalTag `
        $context
    if ($LASTEXITCODE -ne 0) {
        throw 'Windows image candidate build failed'
    }

    $inspection = & $Docker image inspect $LocalTag | ConvertFrom-Json
    if ($inspection.Count -ne 1 `
        -or $inspection[0].Config.User -cne 'ContainerUser' `
        -or $inspection[0].Config.WorkingDir -cne 'C:\__w' `
        -or $inspection[0].Config.Labels.'io.automata.windows-build-inputs.sha256' -cne $buildInputsSha256 `
        -or $inspection[0].Config.Labels.'org.opencontainers.image.revision' -cne $SourceCommit `
        -or $inspection[0].Config.Labels.'io.automata.windows-source-lock.sha256' -cne $sourceLockSha256) {
        throw 'built image configuration differs from the reviewed recipe'
    }

    Write-Output "local_candidate=$LocalTag"
    Write-Output "build_inputs=$retainedBuildInputs"
    Write-Output "build_inputs_sha256=$buildInputsSha256"
    Write-Output "source_lock_sha256=$sourceLockSha256"
    Write-Output 'The local image ID is not a registry identity. Publication and promotion require a separately authorized push, an exact registry @sha256 reference, Hyper-V qualification, and broker/control acceptance.'
}
finally {
    if (Test-Path -LiteralPath $context) {
        Remove-Item -LiteralPath $context -Recurse -Force
    }
}
