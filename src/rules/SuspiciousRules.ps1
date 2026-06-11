<#
.SYNOPSIS
    Defines placeholder suspicious-indicator rules.

.DESCRIPTION
    Rules inspect already-collected suspicious indicator data and return advisory
    findings only. They must not delete tools, stop services, remove tasks, or change policy.
#>

function Invoke-SuspiciousIndicatorRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$AuditData,

        [Parameter()]
        [switch]$IncludeSuspiciousScan
    )

    $findings = @()

    $findings += [ordered]@{
        RuleId      = 'SUS-PLACEHOLDER-001'
        Severity    = 'Info'
        Title       = 'Suspicious indicator rule placeholders loaded'
        Description = if ($IncludeSuspiciousScan) {
            'Suspicious scan was requested, but deep scanning is not implemented yet.'
        }
        else {
            'Suspicious scan was not requested.'
        }
        Status      = 'NotImplemented'
    }

    return $findings
}
