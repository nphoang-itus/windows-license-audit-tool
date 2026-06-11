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

    $suspiciousIndicators = $AuditData['SuspiciousIndicators']
    $indicatorCount = 0
    if ($null -ne $suspiciousIndicators -and $null -ne $suspiciousIndicators['Indicators']) {
        $indicatorCount = @($suspiciousIndicators['Indicators']).Count
    }

    if ($indicatorCount -gt 0) {
        $findings += [ordered]@{
            RuleId      = 'SUS-INDICATORS-001'
            Severity    = 'Warning'
            Title       = 'Suspicious licensing indicators detected'
            Description = "Detected $indicatorCount possible crack or activator indicator(s). Review the SuspiciousIndicators section for evidence."
            Status      = 'Detected'
        }
    }
    else {
        $findings += [ordered]@{
            RuleId      = 'SUS-INDICATORS-001'
            Severity    = 'Info'
            Title       = 'No suspicious licensing indicators detected'
            Description = if ($IncludeSuspiciousScan) {
                'No configured suspicious keywords were matched. The optional limited file-name scan was requested.'
            }
            else {
                'No configured suspicious keywords were matched. The optional limited file-name scan was not requested.'
            }
            Status      = 'NotDetected'
        }
    }

    return $findings
}
