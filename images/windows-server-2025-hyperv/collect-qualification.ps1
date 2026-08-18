[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9._/-]+@sha256:[0-9a-f]{64}$')][string] $Image,
    [Parameter(Mandatory = $true)][string] $Output,
    [string] $Docker = 'docker'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Image.EndsWith(('0' * 64))) {
    throw 'image identity must not be a placeholder'
}
$outputPath = [IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $outputPath) {
    throw 'refusing to overwrite qualification output'
}
$outputParent = Split-Path -Parent $outputPath
New-Item -ItemType Directory -Force -Path $outputParent | Out-Null
$scratch = Join-Path $outputParent ('.qualification-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$probePath = Join-Path $scratch 'probe.ps1'
$guestOutput = Join-Path $scratch 'guest.json'
$container = $null
$json = $null
$removeExitCode = 0

$probe = @'
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Tool([string] $Kind, [string] $Path, [string[]] $Arguments) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "tool is absent: $Path"
    }
    $version = (& $Path @Arguments | Select-Object -First 1).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($version)) {
        throw "tool version probe failed: $Path"
    }
    [ordered]@{
        kind = $Kind
        path = $Path
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
        version = $version
    }
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($identity.Name -notmatch '\\ContainerUser$' `
    -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'qualification probe is not an unprivileged ContainerUser process'
}
if ((Get-ChildItem -Force -LiteralPath 'C:\__w' | Measure-Object).Count -ne 0) {
    throw 'image workspace is not clean'
}

$currentVersion = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$pwsh = Tool 'pwsh' 'C:\Program Files\PowerShell\7\pwsh.exe' @('--version')
$windowsPowerShell = [ordered]@{
    kind = 'powershell'
    path = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
    sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe').Hash.ToLowerInvariant()
    version = (& 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoLogo -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()').Trim()
}
$cmd = [ordered]@{
    kind = 'cmd'
    path = 'C:\Windows\System32\cmd.exe'
    sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\Windows\System32\cmd.exe').Hash.ToLowerInvariant()
    version = (& 'C:\Windows\System32\cmd.exe' /d /s /c ver | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1).Trim()
}
$document = [ordered]@{
    architecture = $env:PROCESSOR_ARCHITECTURE.ToLowerInvariant()
    container_user = $identity.Name
    guest_agent_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\automata\guest\automata-ci-sandbox-guest.exe').Hash.ToLowerInvariant()
    hash_helper_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\automata\tools\hash\automata-sha256.exe').Hash.ToLowerInvariant()
    network_disabled = $true
    os = [ordered]@{
        build = [string]$currentVersion.CurrentBuildNumber
        display_version = [string]$currentVersion.DisplayVersion
        edition_id = [string]$currentVersion.EditionID
        installation_type = [string]$currentVersion.InstallationType
        ubr = [int64]$currentVersion.UBR
    }
    profile_id = 'automata.dev/windows-2025-x64-hyperv-v1'
    schema_version = 1
    tools = @(
        $pwsh,
        $windowsPowerShell,
        $cmd,
        (Tool 'sha256' 'C:\automata\tools\hash\automata-sha256.exe' @('--version')),
        (Tool 'node24' 'C:\automata\externals\node24\node.exe' @('--version'))
    )
    workspace = 'C:\__w'
}
$document | ConvertTo-Json -Depth 8 -Compress
'@

try {
    [IO.File]::WriteAllText($probePath, $probe, [Text.UTF8Encoding]::new($false))
    & $Docker pull $Image | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'could not pull the exact image identity'
    }
    $inspection = & $Docker image inspect $Image | ConvertFrom-Json
    if ($inspection.Count -ne 1 -or -not ($inspection[0].RepoDigests -contains $Image)) {
        throw 'local image does not retain the exact registry identity'
    }
    $labels = $inspection[0].Config.Labels
    $buildInputsSha256 = [string]$labels.'io.automata.windows-build-inputs.sha256'
    $sourceCommit = [string]$labels.'org.opencontainers.image.revision'
    $sourceLockSha256 = [string]$labels.'io.automata.windows-source-lock.sha256'
    if ($buildInputsSha256 -cnotmatch '^[0-9a-f]{64}$' `
        -or $sourceCommit -cnotmatch '^[0-9a-f]{40}$' `
        -or $sourceLockSha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'pulled image build-input labels are absent or invalid'
    }

    $container = (& $Docker create `
        --isolation hyperv `
        --network none `
        --user ContainerUser `
        --entrypoint 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' `
        $Image `
        -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
        -File 'C:\automata\temp\qualification.ps1').Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($container)) {
        throw 'could not create the Hyper-V qualification container'
    }
    & $Docker cp $probePath "${container}:C:\automata\temp\qualification.ps1"
    if ($LASTEXITCODE -ne 0) {
        throw 'could not copy the qualification probe'
    }
    $guestJson = @(& $Docker start --attach $container) -join "`n"
    if ($LASTEXITCODE -ne 0) {
        throw 'qualification probe failed'
    }
    [IO.File]::WriteAllText($guestOutput, $guestJson + "`n", [Text.UTF8Encoding]::new($false))
    $containerInspection = & $Docker inspect $container | ConvertFrom-Json
    if ($containerInspection.Count -ne 1 `
        -or $containerInspection[0].HostConfig.NetworkMode -cne 'none' `
        -or $containerInspection[0].HostConfig.Isolation -cne 'hyperv' `
        -or $containerInspection[0].Config.User -cne 'ContainerUser') {
        throw 'effective qualification boundary differs'
    }

    $guest = Get-Content -Raw -LiteralPath $guestOutput | ConvertFrom-Json
    $qualified = [ordered]@{
        architecture = $guest.architecture
        build_inputs_sha256 = $buildInputsSha256
        container_user = $guest.container_user
        guest_agent_sha256 = $guest.guest_agent_sha256
        hash_helper_sha256 = $guest.hash_helper_sha256
        image = $Image
        isolation = 'hyperv'
        network_disabled = [bool]$guest.network_disabled
        os = $guest.os
        profile_id = $guest.profile_id
        schema_version = 2
        source_commit = $sourceCommit
        source_lock_sha256 = $sourceLockSha256
        tools = $guest.tools
        workspace = $guest.workspace
    }
    $json = $qualified | ConvertTo-Json -Depth 8
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($container)) {
        & $Docker rm --force $container | Out-Null
        $removeExitCode = $LASTEXITCODE
    }
    if (Test-Path -LiteralPath $scratch) {
        Remove-Item -LiteralPath $scratch -Recurse -Force
    }
    if ($removeExitCode -ne 0) {
        throw 'could not remove the qualification container'
    }
}

if ([string]::IsNullOrWhiteSpace($json)) {
    throw 'qualification probe produced no output'
}
[IO.File]::WriteAllText($outputPath, $json + "`n", [Text.UTF8Encoding]::new($false))
