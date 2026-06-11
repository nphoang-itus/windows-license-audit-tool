<#
.SYNOPSIS
    Collects read-only Windows licensing information.

.DESCRIPTION
    Placeholder collector for Windows edition, license channel, activation status,
    partial product key, and Software Protection Platform signals. It must never call
    activation, rearm, key install, key removal, or licensing modification commands.
#>

function Get-WindowsLicenseAuditInfo {
    [CmdletBinding()]
    param()

    try {
        return [ordered]@{
            CollectorName    = 'WindowsLicense'
            Status           = 'Placeholder'
            Edition          = $null
            LicenseStatus    = $null
            LicenseChannel   = $null
            PartialProductKey = $null
            ProductKey       = $null
            ActivationId     = $null
            Notes            = @('Windows license collection will be implemented with read-only queries later.')
        }
    }
    catch {
        return [ordered]@{
            CollectorName = 'WindowsLicense'
            Status        = 'Error'
            Error         = $_.Exception.Message
        }
    }
}
