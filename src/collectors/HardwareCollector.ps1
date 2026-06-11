<#
.SYNOPSIS
    Collects read-only hardware identifiers and platform metadata.

.DESCRIPTION
    Placeholder collector for manufacturer, model, BIOS serial, motherboard serial,
    TPM presence, and network adapter MAC addresses. Sensitive identifiers are masked
    before export. No firmware, device, or network configuration is modified.
#>

function Get-HardwareAuditInfo {
    [CmdletBinding()]
    param()

    try {
        return [ordered]@{
            CollectorName    = 'Hardware'
            Status           = 'Placeholder'
            Manufacturer     = $null
            Model            = $null
            BiosSerialNumber = $null
            BaseboardSerialNumber = $null
            MacAddresses     = @()
            Tpm              = [ordered]@{
                Present = $null
                Ready   = $null
            }
            Notes            = @('Hardware inventory collection will be implemented in a later iteration.')
        }
    }
    catch {
        return [ordered]@{
            CollectorName = 'Hardware'
            Status        = 'Error'
            Error         = $_.Exception.Message
        }
    }
}
