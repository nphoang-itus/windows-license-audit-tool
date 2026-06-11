<#
.SYNOPSIS
    Converts collector output into the normalized report schema.

.DESCRIPTION
    Centralizes the initial JSON schema so future HTML, DOCX, and PDF reports can use
    the same data contract. This module only works with in-memory objects.
#>

function ConvertTo-NormalizedAuditData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$RawData
    )

    return [ordered]@{
        SchemaVersion = '0.1.0'
        ToolName      = 'Windows License Audit Tool'
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        ReadOnlyMode  = $true
        System        = $RawData['System']
        Hardware      = $RawData['Hardware']
        WindowsLicense = $RawData['WindowsLicense']
        OfficeLicense = $RawData['OfficeLicense']
        SuspiciousIndicators = $RawData['SuspiciousIndicators']
        Rules         = @()
    }
}
