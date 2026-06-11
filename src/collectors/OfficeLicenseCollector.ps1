<#
.SYNOPSIS
    Collects read-only Microsoft Office licensing information.

.DESCRIPTION
    Detects common Office OSPP.VBS locations and runs the read-only
    `/dstatusall` diagnostic command when available. The collector must never
    activate, repair, uninstall, change keys, or alter Office licensing state.
#>

function Get-OfficeOsppCandidatePaths {
    [CmdletBinding()]
    param()

    return @(
        'C:\Program Files\Microsoft Office\Office16\OSPP.VBS',
        'C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS',
        'C:\Program Files\Microsoft Office\Office15\OSPP.VBS',
        'C:\Program Files (x86)\Microsoft Office\Office15\OSPP.VBS'
    )
}

function Get-DetectedOfficeOsppPaths {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$CandidatePaths
    )

    $detectedPaths = @()
    foreach ($candidatePath in $CandidatePaths) {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            $detectedPaths += $candidatePath
        }
    }

    return $detectedPaths
}

function Invoke-OfficeOsppReadOnlyDiagnostic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OsppPath,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    try {
        $output = & cscript.exe //Nologo $OsppPath /dstatusall 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            $Warnings.Add("ospp.vbs /dstatusall exited with code $exitCode for '$OsppPath'.") | Out-Null
        }

        return ($output | ForEach-Object { [string]$_ }) -join [Environment]::NewLine
    }
    catch {
        $Warnings.Add("Unable to run ospp.vbs /dstatusall for '$OsppPath'. $($_.Exception.Message)") | Out-Null
        return $null
    }
}

function New-OfficeLicenseProduct {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OsppPath
    )

    return [ordered]@{
        ProductName                  = $null
        LicenseName                  = $null
        LicenseDescriptionOrChannel  = $null
        LicenseStatus                = $null
        InstalledProductKeyLast5     = $null
        KmsMachineName               = $null
        RemainingGrace               = $null
        OsppPath                     = $OsppPath
    }
}

function Set-OfficeLicenseProductValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Product,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FieldName,

        [AllowNull()]
        [string]$Value
    )

    if (-not [string]::IsNullOrWhiteSpace($Value)) {
        $Product[$FieldName] = $Value.Trim()
    }
}

function Complete-OfficeLicenseProduct {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Product
    )

    if ([string]::IsNullOrWhiteSpace([string]$Product['ProductName']) -and
        -not [string]::IsNullOrWhiteSpace([string]$Product['LicenseName'])) {
        $licenseName = [string]$Product['LicenseName']
        $Product['ProductName'] = ($licenseName -split ',', 2)[0].Trim()
    }

    return $Product
}

function Test-OfficeLicenseProductHasData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$Product
    )

    foreach ($key in @('ProductName', 'LicenseName', 'LicenseDescriptionOrChannel', 'LicenseStatus', 'InstalledProductKeyLast5', 'KmsMachineName', 'RemainingGrace')) {
        if (-not [string]::IsNullOrWhiteSpace([string]$Product[$key])) {
            return $true
        }
    }

    return $false
}

function ConvertFrom-OfficeOsppDStatusAllOutput {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$RawOutput,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$OsppPath,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    if ([string]::IsNullOrWhiteSpace($RawOutput)) {
        $Warnings.Add("No output was returned by ospp.vbs /dstatusall for '$OsppPath'.") | Out-Null
        return @()
    }

    $products = @()
    $currentProduct = $null
    $lines = $RawOutput -split "\r?\n"

    foreach ($line in $lines) {
        $trimmedLine = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmedLine)) {
            continue
        }

        if ($trimmedLine -match '^(?i)LICENSE NAME:\s*(.+)$') {
            if ($null -ne $currentProduct -and (Test-OfficeLicenseProductHasData -Product $currentProduct)) {
                $products += Complete-OfficeLicenseProduct -Product $currentProduct
            }

            $currentProduct = New-OfficeLicenseProduct -OsppPath $OsppPath
            Set-OfficeLicenseProductValue -Product $currentProduct -FieldName 'LicenseName' -Value $Matches[1]
            continue
        }

        if ($null -eq $currentProduct) {
            $currentProduct = New-OfficeLicenseProduct -OsppPath $OsppPath
        }

        switch -Regex ($trimmedLine) {
            '^(?i)PRODUCT NAME:\s*(.+)$' {
                Set-OfficeLicenseProductValue -Product $currentProduct -FieldName 'ProductName' -Value $Matches[1]
                continue
            }
            '^(?i)LICENSE DESCRIPTION:\s*(.+)$' {
                Set-OfficeLicenseProductValue -Product $currentProduct -FieldName 'LicenseDescriptionOrChannel' -Value $Matches[1]
                continue
            }
            '^(?i)LICENSE STATUS:\s*(.+)$' {
                Set-OfficeLicenseProductValue -Product $currentProduct -FieldName 'LicenseStatus' -Value $Matches[1]
                continue
            }
            '^(?i)Last 5 characters of installed product key:\s*(.+)$' {
                Set-OfficeLicenseProductValue -Product $currentProduct -FieldName 'InstalledProductKeyLast5' -Value $Matches[1]
                continue
            }
            '^(?i)KMS machine name(?: from DNS)?:\s*(.+)$' {
                Set-OfficeLicenseProductValue -Product $currentProduct -FieldName 'KmsMachineName' -Value $Matches[1]
                continue
            }
            '^(?i)REMAINING GRACE:\s*(.+)$' {
                Set-OfficeLicenseProductValue -Product $currentProduct -FieldName 'RemainingGrace' -Value $Matches[1]
                continue
            }
        }
    }

    if ($null -ne $currentProduct -and (Test-OfficeLicenseProductHasData -Product $currentProduct)) {
        $products += Complete-OfficeLicenseProduct -Product $currentProduct
    }

    if ($products.Count -eq 0) {
        $Warnings.Add("Unable to parse Office product records from ospp.vbs /dstatusall output for '$OsppPath'.") | Out-Null
    }
    else {
        foreach ($product in $products) {
            if ([string]::IsNullOrWhiteSpace([string]$product['LicenseName'])) {
                $Warnings.Add("Parsed an Office product without a license name from '$OsppPath'.") | Out-Null
            }
            if ([string]::IsNullOrWhiteSpace([string]$product['LicenseStatus'])) {
                $Warnings.Add("Parsed an Office product without a license status from '$OsppPath'.") | Out-Null
            }
        }
    }

    return $products
}

function Get-OfficeLicenseAuditInfo {
    [CmdletBinding()]
    param()

    $warnings = [System.Collections.Generic.List[string]]::new()
    $candidatePaths = Get-OfficeOsppCandidatePaths
    $detectedPaths = @(Get-DetectedOfficeOsppPaths -CandidatePaths $candidatePaths)

    if ($detectedPaths.Count -eq 0) {
        return [ordered]@{
            CollectorName    = 'OfficeLicense'
            Status           = 'NotDetected'
            OfficeDetected   = $false
            OsppVbsPaths     = @()
            PathsChecked     = $candidatePaths
            Products         = @()
            Diagnostics      = @()
            Warnings         = @()
        }
    }

    $products = @()
    $diagnostics = @()

    foreach ($osppPath in $detectedPaths) {
        $rawOutput = Invoke-OfficeOsppReadOnlyDiagnostic -OsppPath $osppPath -Warnings $warnings
        $diagnostics += [ordered]@{
            OsppPath  = $osppPath
            Command   = 'cscript.exe //Nologo OSPP.VBS /dstatusall'
            RawOutput = $rawOutput
        }

        $products += ConvertFrom-OfficeOsppDStatusAllOutput -RawOutput $rawOutput -OsppPath $osppPath -Warnings $warnings
    }

    return [ordered]@{
        CollectorName    = 'OfficeLicense'
        Status           = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }
        OfficeDetected   = $true
        OsppVbsPaths     = $detectedPaths
        PathsChecked     = $candidatePaths
        Products         = $products
        Diagnostics      = $diagnostics
        Warnings         = @($warnings)
    }
}
