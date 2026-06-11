<#
.SYNOPSIS
    Defines placeholder read-only licensing rules.

.DESCRIPTION
    Rules inspect normalized collector output and return findings. They must not run
    remediation commands, modify product keys, activate products, or change licensing state.
#>

function Invoke-LicenseAuditRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$AuditData
    )

    $findings = @()

    $findings += [ordered]@{
        RuleId      = 'LIC-PLACEHOLDER-001'
        Severity    = 'Info'
        Title       = 'License rule placeholders loaded'
        Description = 'Read-only Windows and Office license rules will be implemented in a later iteration.'
        Status      = 'NotImplemented'
    }

    return $findings
}
