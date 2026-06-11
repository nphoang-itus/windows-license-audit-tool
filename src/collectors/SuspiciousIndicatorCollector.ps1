<#
.SYNOPSIS
    Collects read-only suspicious indicator placeholders.

.DESCRIPTION
    Placeholder collector for signs commonly associated with licensing tampering, such
    as suspicious services, scheduled tasks, activation tooling names, or policy values.
    Deep scanning is intentionally not implemented yet and no files are deleted.
#>

function Get-SuspiciousIndicatorAuditInfo {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$SkipDeepScan
    )

    try {
        return [ordered]@{
            CollectorName = 'SuspiciousIndicators'
            Status        = if ($SkipDeepScan) { 'Skipped' } else { 'Placeholder' }
            DeepScanRequested = -not [bool]$SkipDeepScan
            Indicators    = @()
            Notes         = @('Suspicious indicator scanning is a placeholder and performs no deep scan yet.')
        }
    }
    catch {
        return [ordered]@{
            CollectorName = 'SuspiciousIndicators'
            Status        = 'Error'
            Error         = $_.Exception.Message
        }
    }
}
