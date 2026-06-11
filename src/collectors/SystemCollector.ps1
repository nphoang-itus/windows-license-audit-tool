<#
.SYNOPSIS
    Collects read-only operating system and environment metadata.

.DESCRIPTION
    Placeholder collector for system facts such as OS name, version, build, install
    date, computer name, and current user. Sensitive fields are masked during report
    export. No system settings are changed.
#>

function Get-SystemAuditInfo {
    [CmdletBinding()]
    param()

    try {
        return [ordered]@{
            CollectorName = 'System'
            Status        = 'Placeholder'
            ComputerName  = $env:COMPUTERNAME
            UserName      = $env:USERNAME
            OsName        = $null
            OsVersion     = $null
            OsBuild       = $null
            CollectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
            Notes         = @('System metadata collection will be implemented in a later iteration.')
        }
    }
    catch {
        return [ordered]@{
            CollectorName = 'System'
            Status        = 'Error'
            Error         = $_.Exception.Message
        }
    }
}
