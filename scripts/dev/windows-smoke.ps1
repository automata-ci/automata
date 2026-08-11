[CmdletBinding()]
param(
    [string]$Listen = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw 'the native Windows smoke test must run on Windows'
}

if ([string]::IsNullOrWhiteSpace($Listen)) {
    $portProbe = [System.Net.Sockets.TcpListener]::new(
        [System.Net.IPAddress]::Loopback,
        0
    )
    $portProbe.Start()
    $Listen = "127.0.0.1:$(([System.Net.IPEndPoint]$portProbe.LocalEndpoint).Port)"
    $portProbe.Stop()
}
elseif ($Listen -notmatch '^127\.0\.0\.1:([1-9][0-9]{0,4})$' -or
    [int]$Matches[1] -gt 65535) {
    throw 'Listen must be a literal 127.0.0.1 endpoint with a valid nonzero port'
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$scratch = Join-Path $repositoryRoot 'target\windows-smoke'
$stdoutLog = Join-Path $scratch 'preview.stdout.log'
$stderrLog = Join-Path $scratch 'preview.stderr.log'
$origin = "http://$Listen"
$preview = $null

function Invoke-Cargo {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "cargo exited with status $LASTEXITCODE"
    }
}

function Read-PreviewFailure {
    $detail = @()
    foreach ($path in @($stdoutLog, $stderrLog)) {
        if (Test-Path -LiteralPath $path) {
            $content = Get-Content -LiteralPath $path -Raw
            if ($content.Length -gt 4096) {
                $content = $content.Substring($content.Length - 4096)
            }
            if ($content.Length -gt 0) {
                $detail += "${path}:`n$content"
            }
        }
    }
    return ($detail -join "`n")
}

Push-Location $repositoryRoot
try {
    New-Item -ItemType Directory -Force -Path $scratch | Out-Null
    Remove-Item -Force -ErrorAction SilentlyContinue $stdoutLog, $stderrLog

    Invoke-Cargo @('build', '--locked', '--bin', 'automata', '--bin', 'automata-runner')

    $preview = Start-Process `
        -FilePath (Join-Path $repositoryRoot 'target\debug\automata.exe') `
        -ArgumentList @('preview', '--listen', $Listen) `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog `
        -PassThru

    $health = $null
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(120)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if ($preview.HasExited) {
            $detail = Read-PreviewFailure
            throw "preview exited before becoming healthy`n$detail"
        }
        try {
            $health = Invoke-RestMethod -Uri "$origin/healthz" -TimeoutSec 5
            break
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if ($null -eq $health) {
        $detail = Read-PreviewFailure
        throw "preview did not become healthy before the deadline`n$detail"
    }
    if ($health.status -ne 'ok' -or [string]::IsNullOrWhiteSpace($health.version)) {
        throw 'preview returned an invalid health document'
    }

    $readiness = Invoke-WebRequest -UseBasicParsing -Uri "$origin/readyz" -TimeoutSec 5
    if ($readiness.StatusCode -ne 200 -or $readiness.Content.Trim() -ne 'ready') {
        throw 'preview did not return the exact ready state'
    }

    $repositories = Invoke-WebRequest -UseBasicParsing -Uri "$origin/repositories" -TimeoutSec 30
    if ($repositories.StatusCode -ne 200 -or
        -not $repositories.Content.StartsWith('<!doctype html>') -or
        -not $repositories.Content.Contains('<title>Repositories') -or
        -not $repositories.Content.Contains('Automata</title>')) {
        throw 'preview did not return the expected server-rendered repository page'
    }

    & (Join-Path $repositoryRoot 'target\debug\automata.exe') `
        admin --server-url "$origin/" status
    if ($LASTEXITCODE -ne 0) {
        throw "automata admin status exited with status $LASTEXITCODE"
    }

    $doctorOutput = & (Join-Path $repositoryRoot 'target\debug\automata-runner.exe') `
        doctor --server $origin --json
    if ($LASTEXITCODE -ne 0) {
        throw "automata-runner doctor exited with status $LASTEXITCODE"
    }
    $doctor = $doctorOutput | ConvertFrom-Json
    if ($doctor.os -ne 'windows' -or $doctor.arch -ne 'x86_64') {
        throw 'runner doctor returned an unexpected native platform identity'
    }
    $processProbe = $doctor.capability_probes | Where-Object {
        $_.capability -eq 'core.process-exec/v1'
    }
    if ($null -eq $processProbe -or $processProbe.status -ne 'usable') {
        throw 'runner doctor did not prove native process execution'
    }
    if ($doctor.server.status -ne 'healthy') {
        throw 'runner doctor did not report the preview as healthy'
    }

    Write-Host "Windows smoke test passed for $origin"
}
finally {
    if ($null -ne $preview -and -not $preview.HasExited) {
        Stop-Process -Id $preview.Id -Force
        $preview.WaitForExit()
    }
    Pop-Location
}
