<#
.SYNOPSIS
    Collects read-only hardware identifiers and platform metadata.

.DESCRIPTION
    Uses CIM read queries for platform, CPU, memory, motherboard, BIOS, physical
    disk, and active network adapter metadata. Query failures are recorded as
    warnings so a partial report can still be generated.
#>

function Invoke-HardwareCimQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ClassName,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    try {
        return Get-CimInstance -ClassName $ClassName -ErrorAction Stop
    }
    catch {
        $Warnings.Add("Unable to query $ClassName. $($_.Exception.Message)") | Out-Null
        return $null
    }
}

function Get-HardwareAuditInfo {
    [CmdletBinding()]
    param()

    $warnings = [System.Collections.Generic.List[string]]::new()

    $computerSystem = Invoke-HardwareCimQuery -ClassName 'Win32_ComputerSystem' -Warnings $warnings
    $processor = @(Invoke-HardwareCimQuery -ClassName 'Win32_Processor' -Warnings $warnings | Select-Object -First 1)
    $baseboard = Invoke-HardwareCimQuery -ClassName 'Win32_BaseBoard' -Warnings $warnings
    $bios = Invoke-HardwareCimQuery -ClassName 'Win32_BIOS' -Warnings $warnings
    $diskDrives = @(Invoke-HardwareCimQuery -ClassName 'Win32_DiskDrive' -Warnings $warnings)
    $networkAdapters = @(Invoke-HardwareCimQuery -ClassName 'Win32_NetworkAdapter' -Warnings $warnings)

    $totalRamGb = $null
    if ($null -ne $computerSystem -and $null -ne $computerSystem.TotalPhysicalMemory) {
        $totalRamGb = [math]::Round(([double]$computerSystem.TotalPhysicalMemory / 1GB), 2)
    }

    $physicalDisks = @()
    foreach ($disk in $diskDrives) {
        if ($null -eq $disk) {
            continue
        }

        $physicalDisks += [ordered]@{
            Model        = if ($null -ne $disk.Model) { ([string]$disk.Model).Trim() } else { $null }
            SerialNumber = if ($null -ne $disk.SerialNumber) { ([string]$disk.SerialNumber).Trim() } else { $null }
        }
    }

    $activeMacAddresses = @()
    foreach ($adapter in $networkAdapters) {
        if ($null -eq $adapter -or -not $adapter.NetEnabled -or [string]::IsNullOrWhiteSpace($adapter.MACAddress)) {
            continue
        }

        $activeMacAddresses += ([string]$adapter.MACAddress).Trim()
    }

    return [ordered]@{
        CollectorName      = 'Hardware'
        Status             = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }
        Manufacturer       = if ($null -ne $computerSystem) { $computerSystem.Manufacturer } else { $null }
        Model              = if ($null -ne $computerSystem) { $computerSystem.Model } else { $null }
        CpuName            = if ($processor.Count -gt 0 -and $null -ne $processor[0]) { $processor[0].Name } else { $null }
        TotalRamGb         = $totalRamGb
        Motherboard        = [ordered]@{
            Manufacturer = if ($null -ne $baseboard) { $baseboard.Manufacturer } else { $null }
            Product      = if ($null -ne $baseboard) { $baseboard.Product } else { $null }
            SerialNumber = if ($null -ne $baseboard) { $baseboard.SerialNumber } else { $null }
        }
        BiosSerialNumber   = if ($null -ne $bios) { $bios.SerialNumber } else { $null }
        PhysicalDisks      = $physicalDisks
        ActiveMacAddresses = $activeMacAddresses
        Warnings           = @($warnings)
    }
}
