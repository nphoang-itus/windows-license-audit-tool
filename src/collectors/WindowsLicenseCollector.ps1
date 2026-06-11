<#
.SYNOPSIS
    Collects read-only Windows licensing information.

.DESCRIPTION
    Uses CIM read queries and read-only slmgr diagnostic commands to collect Windows
    license state. The collector must never activate, deactivate, install, uninstall,
    rearm, or otherwise modify Windows licensing.
#>

function Invoke-WindowsLicenseCimQuery {
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

function Get-CimPropertyValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$PropertyNames
    )

    if ($null -eq $InputObject) {
        return $null
    }

    foreach ($propertyName in $PropertyNames) {
        $property = $InputObject.PSObject.Properties[$propertyName]
        if ($null -ne $property -and $null -ne $property.Value) {
            return $property.Value
        }
    }

    return $null
}

function Convert-LicenseStatusCodeToText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$StatusCode
    )

    if ($null -eq $StatusCode) {
        return $null
    }

    switch ([int]$StatusCode) {
        0 { return 'Unlicensed' }
        1 { return 'Licensed' }
        2 { return 'Out-of-Box Grace Period' }
        3 { return 'Out-of-Tolerance Grace Period' }
        4 { return 'Non-Genuine Grace Period' }
        5 { return 'Notification' }
        6 { return 'Extended Grace Period' }
        default { return "Unknown ($StatusCode)" }
    }
}

function Convert-EmptyLicenseValueToNull {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    if ($Value -is [ValueType] -and $Value -is [System.IConvertible]) {
        try {
            if ([double]$Value -eq 0) {
                return $null
            }
        }
        catch {
            return $Value
        }
    }

    if ($Value -is [string] -and $Value.Trim() -eq '0') {
        return $null
    }

    return $Value
}

function Select-WindowsLicensingProduct {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Products
    )

    $windowsProducts = @(
        $Products |
            Where-Object {
                $null -ne $_ -and
                -not [string]::IsNullOrWhiteSpace($_.PartialProductKey) -and
                (
                    ([string]$_.Name -match 'Windows') -or
                    ([string]$_.Description -match 'Windows')
                )
            }
    )

    if ($windowsProducts.Count -eq 0) {
        return $null
    }

    $licensed = @($windowsProducts | Where-Object { $_.LicenseStatus -eq 1 } | Select-Object -First 1)
    if ($licensed.Count -gt 0) {
        return $licensed[0]
    }

    return @($windowsProducts | Select-Object -First 1)[0]
}

function Invoke-SlmgrReadOnlyDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('/xpr', '/dlv')]
        [string]$Argument,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    $slmgrPath = Join-Path -Path $env:windir -ChildPath 'System32\slmgr.vbs'
    if (-not (Test-Path -LiteralPath $slmgrPath -PathType Leaf)) {
        $Warnings.Add("Unable to run slmgr $Argument. slmgr.vbs was not found.") | Out-Null
        return $null
    }

    try {
        $output = & cscript.exe //NoLogo $slmgrPath $Argument 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            $Warnings.Add("slmgr $Argument exited with code $exitCode.") | Out-Null
        }

        return ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    }
    catch {
        $Warnings.Add("Unable to run slmgr $Argument. $($_.Exception.Message)") | Out-Null
        return $null
    }
}

function Get-WindowsLicenseAuditInfo {
    [CmdletBinding()]
    param()

    $warnings = [System.Collections.Generic.List[string]]::new()

    $os = Invoke-WindowsLicenseCimQuery -ClassName 'Win32_OperatingSystem' -Warnings $warnings
    $service = Invoke-WindowsLicenseCimQuery -ClassName 'SoftwareLicensingService' -Warnings $warnings
    $products = @(Invoke-WindowsLicenseCimQuery -ClassName 'SoftwareLicensingProduct' -Warnings $warnings)
    $windowsProduct = Select-WindowsLicensingProduct -Products $products

    if ($null -eq $windowsProduct) {
        $warnings.Add('No Windows SoftwareLicensingProduct with a partial product key was found.') | Out-Null
    }

    $oemKey = Get-CimPropertyValue -InputObject $service -PropertyNames @('OA3xOriginalProductKey')
    $kmsHost = Convert-EmptyLicenseValueToNull -Value (Get-CimPropertyValue -InputObject $windowsProduct -PropertyNames @(
        'DiscoveredKeyManagementServiceMachineName',
        'KeyManagementServiceMachine'
    ))
    $kmsPort = Convert-EmptyLicenseValueToNull -Value (Get-CimPropertyValue -InputObject $windowsProduct -PropertyNames @(
        'DiscoveredKeyManagementServicePort',
        'KeyManagementServicePort'
    ))

    return [ordered]@{
        CollectorName         = 'WindowsLicense'
        Status                = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }
        WindowsCaption        = if ($null -ne $os) { $os.Caption } else { $null }
        Version               = if ($null -ne $os) { $os.Version } else { $null }
        BuildNumber           = if ($null -ne $os) { $os.BuildNumber } else { $null }
        Architecture          = if ($null -ne $os) { $os.OSArchitecture } else { $null }
        ProductId             = if ($null -ne $os) { $os.SerialNumber } else { $null }
        LicenseName           = if ($null -ne $windowsProduct) { $windowsProduct.Name } else { $null }
        LicenseDescription    = if ($null -ne $windowsProduct) { $windowsProduct.Description } else { $null }
        LicenseStatusCode     = if ($null -ne $windowsProduct) { $windowsProduct.LicenseStatus } else { $null }
        LicenseStatusText     = if ($null -ne $windowsProduct) { Convert-LicenseStatusCodeToText -StatusCode $windowsProduct.LicenseStatus } else { $null }
        PartialProductKey     = if ($null -ne $windowsProduct) { $windowsProduct.PartialProductKey } else { $null }
        GracePeriodRemaining  = if ($null -ne $windowsProduct) { $windowsProduct.GracePeriodRemaining } else { $null }
        OemKeyPresent         = -not [string]::IsNullOrWhiteSpace([string]$oemKey)
        KmsHost               = $kmsHost
        KmsPort               = $kmsPort
        Diagnostics           = [ordered]@{
            SlmgrXpr = Invoke-SlmgrReadOnlyDiagnostic -Argument '/xpr' -Warnings $warnings
            SlmgrDlv = Invoke-SlmgrReadOnlyDiagnostic -Argument '/dlv' -Warnings $warnings
        }
        Warnings              = @($warnings)
    }
}
