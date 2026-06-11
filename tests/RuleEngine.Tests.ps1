Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path -Path $repoRoot -ChildPath 'src\rules\RuleEngine.ps1')

function ConvertTo-TestHashtable {
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
            $hashtable[$key] = ConvertTo-TestHashtable -InputObject $InputObject[$key]
        }
        return $hashtable
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += ConvertTo-TestHashtable -InputObject $item
        }
        return $items
    }

    if ($InputObject -is [pscustomobject]) {
        $hashtable = [ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $hashtable[$property.Name] = ConvertTo-TestHashtable -InputObject $property.Value
        }
        return $hashtable
    }

    return $InputObject
}

function Invoke-FixtureRuleEngine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FixtureName
    )

    $fixturePath = Join-Path -Path $PSScriptRoot -ChildPath "fixtures\$FixtureName"
    $auditData = ConvertTo-TestHashtable -InputObject (Get-Content -LiteralPath $fixturePath -Raw | ConvertFrom-Json)
    return Invoke-AuditRuleEngine -AuditData $auditData
}

Describe 'Rule engine verdicts from fixture JSON' {
    It 'classifies a licensed OEM machine with OEM key present as GENUINE_LIKELY' {
        $result = Invoke-FixtureRuleEngine -FixtureName 'licensed-oem.json'

        $result.windowsVerdict | Should Be 'GENUINE_LIKELY'
        $result.overallRisk | Should Be 'GENUINE_LIKELY'
        $result.riskScore | Should Be 0
    }

    It 'classifies a licensed Retail machine without OEM key as ACTIVATED_REVIEW_REQUIRED' {
        $result = Invoke-FixtureRuleEngine -FixtureName 'licensed-retail-no-oem.json'

        $result.windowsVerdict | Should Be 'ACTIVATED_REVIEW_REQUIRED'
        $result.overallRisk | Should Be 'ACTIVATED_REVIEW_REQUIRED'
    }

    It 'classifies unlicensed Windows as NOT_ACTIVATED' {
        $result = Invoke-FixtureRuleEngine -FixtureName 'unlicensed-windows.json'

        $result.windowsVerdict | Should Be 'NOT_ACTIVATED'
        $result.overallRisk | Should Be 'NOT_ACTIVATED'
        $result.riskScore | Should Be 40
    }

    It 'classifies a KMS machine with a trusted host as organization-context review or likely genuine for organization' {
        $result = Invoke-FixtureRuleEngine -FixtureName 'kms-trusted.json'

        (@('ACTIVATED_REVIEW_REQUIRED', 'GENUINE_LIKELY_FOR_ORG') -contains $result.windowsVerdict) | Should Be $true
        (@('ACTIVATED_REVIEW_REQUIRED', 'GENUINE_LIKELY_FOR_ORG') -contains $result.overallRisk) | Should Be $true
        $result.riskScore | Should Be 0
    }

    It 'classifies a KMS machine with an untrusted host as SUSPICIOUS' {
        $result = Invoke-FixtureRuleEngine -FixtureName 'kms-untrusted.json'

        $result.windowsVerdict | Should Be 'SUSPICIOUS'
        $result.overallRisk | Should Be 'SUSPICIOUS'
        $result.riskScore | Should Be 35
    }

    It 'classifies NonGenuineGrace as HIGH_RISK' {
        $result = Invoke-FixtureRuleEngine -FixtureName 'non-genuine-grace.json'

        $result.windowsVerdict | Should Be 'HIGH_RISK'
        $result.overallRisk | Should Be 'HIGH_RISK'
        $result.riskScore | Should Be 80
    }

    It 'classifies Office NOTIFICATIONS as Office review required' {
        $result = Invoke-FixtureRuleEngine -FixtureName 'office-notifications.json'

        $result.officeVerdict | Should Be 'ACTIVATED_REVIEW_REQUIRED'
        $result.overallRisk | Should Be 'ACTIVATED_REVIEW_REQUIRED'
        $result.riskScore | Should Be 40
    }

    It 'increases risk score for a suspicious scheduled task keyword' {
        $result = Invoke-FixtureRuleEngine -FixtureName 'suspicious-scheduled-task.json'

        $result.suspiciousIndicatorVerdict | Should Be 'HIGH_RISK'
        $result.overallRisk | Should Be 'HIGH_RISK'
        $result.riskScore | Should Be 40
        ($result.reasons -join ' ') | Should Match 'scheduled task'
    }

    It 'classifies suspicious filename-only evidence as a low risk indicator' {
        $result = Invoke-FixtureRuleEngine -FixtureName 'suspicious-filename-only.json'

        $result.suspiciousIndicatorVerdict | Should Be 'SUSPICIOUS'
        $result.overallRisk | Should Be 'SUSPICIOUS'
        $result.riskScore | Should Be 10
    }
}
