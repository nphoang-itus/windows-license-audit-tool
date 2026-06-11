<#
.SYNOPSIS
    Collects read-only Microsoft Office licensing information.

.DESCRIPTION
    Placeholder collector for installed Office products, licensing channel, subscription
    or volume-license hints, and partial keys where available. It must not activate,
    repair, uninstall, change keys, or alter Office licensing state.
#>

function Get-OfficeLicenseAuditInfo {
    [CmdletBinding()]
    param()

    try {
        return [ordered]@{
            CollectorName = 'OfficeLicense'
            Status        = 'Placeholder'
            Products      = @()
            Notes         = @('Office license collection will be implemented with read-only queries later.')
        }
    }
    catch {
        return [ordered]@{
            CollectorName = 'OfficeLicense'
            Status        = 'Error'
            Error         = $_.Exception.Message
        }
    }
}
