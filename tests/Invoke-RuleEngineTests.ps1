<#
.SYNOPSIS
    Lightweight rule-engine tests using mock JSON inputs.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path -Path $PSScriptRoot -ChildPath '..\src\rules\RuleEngine.ps1')

function ConvertTo-Hashtable {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject
    )

    if ($null -eq $InputObject) {
        return $null
    }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $hashtable = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            $hashtable[$key] = ConvertTo-Hashtable -InputObject $InputObject[$key]
        }
        return $hashtable
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ConvertTo-Hashtable -InputObject $item
        }
        return $items
    }

    if ($InputObject -is [pscustomobject]) {
        $hashtable = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $hashtable[$property.Name] = ConvertTo-Hashtable -InputObject $property.Value
        }
        return $hashtable
    }

    return $InputObject
}

function Assert-Equal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Actual,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$Expected,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected' but got '$Actual'."
    }
}

$cases = @(
    @{
        File = 'licensed-clean.json'
        WindowsVerdict = 'ACTIVATED_REVIEW_REQUIRED'
        OfficeVerdict = 'CLEAN'
        SuspiciousIndicatorVerdict = 'CLEAN'
        OverallRisk = 'ACTIVATED_REVIEW_REQUIRED'
        RiskScore = 0
    },
    @{
        File = 'windows-not-activated.json'
        WindowsVerdict = 'NOT_ACTIVATED'
        OfficeVerdict = 'CLEAN'
        SuspiciousIndicatorVerdict = 'CLEAN'
        OverallRisk = 'NOT_ACTIVATED'
        RiskScore = 40
    },
    @{
        File = 'non-genuine-high-risk.json'
        WindowsVerdict = 'HIGH_RISK'
        OfficeVerdict = 'CLEAN'
        SuspiciousIndicatorVerdict = 'CLEAN'
        OverallRisk = 'HIGH_RISK'
        RiskScore = 80
    },
    @{
        File = 'untrusted-kms-review.json'
        WindowsVerdict = 'SUSPICIOUS'
        OfficeVerdict = 'CLEAN'
        SuspiciousIndicatorVerdict = 'CLEAN'
        OverallRisk = 'SUSPICIOUS'
        RiskScore = 35
    },
    @{
        File = 'office-notifications.json'
        WindowsVerdict = 'GENUINE_LIKELY'
        OfficeVerdict = 'ACTIVATED_REVIEW_REQUIRED'
        SuspiciousIndicatorVerdict = 'CLEAN'
        OverallRisk = 'ACTIVATED_REVIEW_REQUIRED'
        RiskScore = 40
    },
    @{
        File = 'suspicious-task.json'
        WindowsVerdict = 'GENUINE_LIKELY'
        OfficeVerdict = 'CLEAN'
        SuspiciousIndicatorVerdict = 'HIGH_RISK'
        OverallRisk = 'HIGH_RISK'
        RiskScore = 40
    }
)

foreach ($case in $cases) {
    $mockPath = Join-Path -Path $PSScriptRoot -ChildPath "mock-json\$($case.File)"
    $auditData = ConvertTo-Hashtable -InputObject (Get-Content -LiteralPath $mockPath -Raw | ConvertFrom-Json)
    $result = Invoke-AuditRuleEngine -AuditData $auditData

    Assert-Equal -Actual $result.windowsVerdict -Expected $case.WindowsVerdict -Message "$($case.File) windowsVerdict mismatch."
    Assert-Equal -Actual $result.officeVerdict -Expected $case.OfficeVerdict -Message "$($case.File) officeVerdict mismatch."
    Assert-Equal -Actual $result.suspiciousIndicatorVerdict -Expected $case.SuspiciousIndicatorVerdict -Message "$($case.File) suspiciousIndicatorVerdict mismatch."
    Assert-Equal -Actual $result.overallRisk -Expected $case.OverallRisk -Message "$($case.File) overallRisk mismatch."
    Assert-Equal -Actual $result.riskScore -Expected $case.RiskScore -Message "$($case.File) riskScore mismatch."
}

Write-Output "Rule engine tests passed: $($cases.Count)"
