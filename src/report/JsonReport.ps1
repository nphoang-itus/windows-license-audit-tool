<#
.SYNOPSIS
    Exports normalized audit data as JSON.

.DESCRIPTION
    Writes the first supported report format for the tool. HTML, DOCX, and PDF
    generation will be added later and should consume the same normalized schema.
#>

function Export-AuditJsonReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AuditReport,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDir
    )

    try {
        $resolvedOutputDir = Ensure-AuditDirectory -Path $OutputDir
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $fileName = "windows-license-audit-$timestamp.json"
        $jsonPath = Join-Path -Path $resolvedOutputDir -ChildPath $fileName

        $AuditReport |
            ConvertTo-Json -Depth 20 |
            Set-Content -LiteralPath $jsonPath -Encoding UTF8

        return $jsonPath
    }
    catch {
        throw "Unable to export JSON report. $($_.Exception.Message)"
    }
}
