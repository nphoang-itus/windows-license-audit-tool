<#
.SYNOPSIS
    Simple runner for the read-only Windows License Audit Tool.

.DESCRIPTION
    Calls src/main.ps1 with safe defaults, exports JSON and HTML reports, and
    opens the generated HTML report in the default browser unless -NoOpen is set.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDir,

    [Parameter()]
    [switch]$IncludeSuspiciousScan,

    [Parameter()]
    [switch]$NoOpen,

    [Parameter()]
    [switch]$VerboseMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    $scriptRoot = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
        $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    }

    if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
        $scriptRoot = (Get-Location).Path
    }

    if ([string]::IsNullOrWhiteSpace($OutputDir)) {
        $OutputDir = Join-Path -Path $scriptRoot -ChildPath 'exports'
    }

    $mainScript = Join-Path -Path $scriptRoot -ChildPath 'src\main.ps1'
    if (-not (Test-Path -LiteralPath $mainScript -PathType Leaf)) {
        throw "Cannot find audit entry point: $mainScript"
    }

    $arguments = @{
        OutputDir = $OutputDir
    }

    if ($IncludeSuspiciousScan) {
        $arguments['IncludeSuspiciousScan'] = $true
    }

    if ($VerboseMode) {
        $arguments['VerboseMode'] = $true
    }

    $output = & $mainScript @arguments
    $output | ForEach-Object { Write-Output $_ }

    $htmlPath = $null
    foreach ($line in $output) {
        if ([string]$line -match '^HTML report exported to:\s*(.+)$') {
            $htmlPath = $Matches[1].Trim()
        }
    }

    if (-not $NoOpen -and -not [string]::IsNullOrWhiteSpace($htmlPath)) {
        if (Test-Path -LiteralPath $htmlPath -PathType Leaf) {
            Start-Process -FilePath $htmlPath | Out-Null
            Write-Output "Opened HTML report: $htmlPath"
        }
        else {
            Write-Warning "HTML report was not found after export: $htmlPath"
        }
    }
}
catch {
    Write-Error -Message "Audit runner failed. $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
