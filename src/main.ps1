<#
.SYNOPSIS
    Entry point for the read-only Windows License Audit Tool.

.DESCRIPTION
    Loads collector, rule, report, and utility modules; gathers placeholder audit data;
    normalizes and masks sensitive values; evaluates read-only rules; and exports JSON.
    This script must not activate Windows or Office, change keys, delete files, or remove software.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDir = (Join-Path -Path $PSScriptRoot -ChildPath '..\exports'),

    [Parameter()]
    [switch]$IncludeSuspiciousScan,

    [Parameter()]
    [switch]$VerboseMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($VerboseMode) {
    $VerbosePreference = 'Continue'
}

function Import-AuditModule {
    <#
    .SYNOPSIS
        Dot-sources a local PowerShell module file with defensive error handling.
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required module was not found: $Path"
    }

    Write-Verbose "Loading module: $Path"
    . $Path
}

try {
    $modulePaths = @(
        'utils\ErrorHandling.ps1',
        'utils\Masking.ps1',
        'collectors\SystemCollector.ps1',
        'collectors\HardwareCollector.ps1',
        'collectors\WindowsLicenseCollector.ps1',
        'collectors\OfficeLicenseCollector.ps1',
        'collectors\SuspiciousIndicatorCollector.ps1',
        'report\Normalizer.ps1',
        'rules\LicenseRules.ps1',
        'rules\SuspiciousRules.ps1',
        'rules\RuleEngine.ps1',
        'report\JsonReport.ps1'
    )

    foreach ($relativePath in $modulePaths) {
        Import-AuditModule -Path (Join-Path -Path $PSScriptRoot -ChildPath $relativePath)
    }

    Ensure-AuditDirectory -Path $OutputDir | Out-Null

    Write-Verbose 'Collecting read-only audit data.'
    if ($IncludeSuspiciousScan) {
        $suspiciousIndicators = Get-SuspiciousIndicatorAuditInfo
    }
    else {
        $suspiciousIndicators = Get-SuspiciousIndicatorAuditInfo -SkipDeepScan
    }

    $rawAuditData = [ordered]@{
        System               = Get-SystemAuditInfo
        Hardware             = Get-HardwareAuditInfo
        WindowsLicense       = Get-WindowsLicenseAuditInfo
        OfficeLicense        = Get-OfficeLicenseAuditInfo
        SuspiciousIndicators = $suspiciousIndicators
    }

    Write-Verbose 'Normalizing audit data.'
    $normalizedAuditData = ConvertTo-NormalizedAuditData -RawData $rawAuditData

    Write-Verbose 'Running read-only rules.'
    $ruleResults = Invoke-AuditRuleEngine -AuditData $normalizedAuditData -IncludeSuspiciousScan:$IncludeSuspiciousScan
    $normalizedAuditData['Rules'] = $ruleResults

    Write-Verbose 'Masking sensitive report values.'
    $safeReport = Protect-AuditReportSensitiveData -InputObject $normalizedAuditData

    $jsonPath = Export-AuditJsonReport -AuditReport $safeReport -OutputDir $OutputDir
    Write-Output "JSON report exported to: $jsonPath"
}
catch {
    Write-AuditError -Message 'Audit failed.' -ErrorRecord $_
    exit 1
}
