<#
.SYNOPSIS
    Runs all read-only audit rules.

.DESCRIPTION
    Coordinates license and suspicious-indicator rule modules. The engine returns
    normalized findings and never performs remediation.
#>

function Invoke-AuditRuleEngine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$AuditData,

        [Parameter()]
        [switch]$IncludeSuspiciousScan
    )

    $results = @()

    try {
        $results += Invoke-LicenseAuditRules -AuditData $AuditData
        $results += Invoke-SuspiciousIndicatorRules -AuditData $AuditData -IncludeSuspiciousScan:$IncludeSuspiciousScan
    }
    catch {
        $results += [ordered]@{
            RuleId      = 'ENGINE-ERROR-001'
            Severity    = 'Error'
            Title       = 'Rule engine failed'
            Description = $_.Exception.Message
            Status      = 'Error'
        }
    }

    return $results
}
