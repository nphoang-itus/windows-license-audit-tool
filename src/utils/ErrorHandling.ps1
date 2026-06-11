<#
.SYNOPSIS
    Shared defensive error-handling helpers for the audit tool.

.DESCRIPTION
    Keeps common validation and logging behavior in one place. These helpers are
    read-only and must not alter Windows, Office, licensing state, files outside
    requested output paths, or installed software.
#>

function Ensure-AuditDirectory {
    <#
    .SYNOPSIS
        Ensures an export directory exists.

    .DESCRIPTION
        Creates only the requested output directory when needed. This is the only
        expected write path in the initial JSON-only skeleton.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        return (Resolve-Path -LiteralPath $Path).Path
    }
    catch {
        throw "Unable to prepare output directory '$Path'. $($_.Exception.Message)"
    }
}

function Write-AuditError {
    <#
    .SYNOPSIS
        Writes a consistent non-terminating error message for top-level failures.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,

        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    Write-Error -Message "$Message $($ErrorRecord.Exception.Message)" -ErrorAction Continue
}
