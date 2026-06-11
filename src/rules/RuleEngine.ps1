<#
.SYNOPSIS
    Produces evidence-based read-only license audit verdicts.

.DESCRIPTION
    Evaluates normalized collector output for Windows, Office, suspicious
    indicators, and overall risk. This module does not collect data and never
    performs remediation or licensing changes.
#>

function Get-RuleConfigPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$FileName
    )

    return (Join-Path -Path $PSScriptRoot -ChildPath "..\..\config\$FileName")
}

function Get-TrustedKmsHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Reasons
    )

    $configPath = Get-RuleConfigPath -FileName 'trusted-kms-hosts.json'
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        $Reasons.Add("Trusted KMS host config was not found: $configPath") | Out-Null
        return @()
    }

    try {
        $config = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $hosts = @()
        foreach ($hostName in @($config.trustedKmsHosts)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$hostName)) {
                $hosts += ([string]$hostName).Trim().ToLowerInvariant()
            }
        }
        return @($hosts | Select-Object -Unique)
    }
    catch {
        $Reasons.Add("Unable to load trusted KMS host config '$configPath'. $($_.Exception.Message)") | Out-Null
        return @()
    }
}

function Get-AuditValue {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    if ($null -eq $Object) {
        return $null
    }

    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) {
        return $Object[$Name]
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Test-TrustedKmsHost {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$KmsHost,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$TrustedHosts
    )

    if ([string]::IsNullOrWhiteSpace($KmsHost)) {
        return $true
    }

    return $TrustedHosts -contains $KmsHost.Trim().ToLowerInvariant()
}

function Add-Risk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ref]$RiskScore,

        [Parameter(Mandatory)]
        [int]$Points
    )

    $RiskScore.Value = [int]$RiskScore.Value + $Points
}

function Get-WindowsLicenseVerdict {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$WindowsLicense,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$TrustedKmsHosts,

        [Parameter(Mandatory)]
        [ref]$RiskScore,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Reasons,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Recommendations
    )

    if ($null -eq $WindowsLicense) {
        $Reasons.Add('Windows license data is unavailable.') | Out-Null
        $Recommendations.Add('Review Windows activation status manually because license collector data is unavailable.') | Out-Null
        return 'NEED_MANUAL_REVIEW'
    }

    $statusCode = Get-AuditValue -Object $WindowsLicense -Name 'LicenseStatusCode'
    $statusText = [string](Get-AuditValue -Object $WindowsLicense -Name 'LicenseStatusText')
    $description = [string](Get-AuditValue -Object $WindowsLicense -Name 'LicenseDescription')
    $kmsHost = [string](Get-AuditValue -Object $WindowsLicense -Name 'KmsHost')
    $oemKeyPresent = [bool](Get-AuditValue -Object $WindowsLicense -Name 'OemKeyPresent')

    $usesKms = ($description -match 'KMS') -or -not [string]::IsNullOrWhiteSpace($kmsHost)

    if ($statusCode -eq 1 -or $statusText -match '(?i)^Licensed$') {
        $Reasons.Add('Windows reports Licensed status.') | Out-Null
        if ($usesKms) {
            $Reasons.Add('KMS activation requires organization context.') | Out-Null
            if (-not (Test-TrustedKmsHost -KmsHost $kmsHost -TrustedHosts $TrustedKmsHosts)) {
                Add-Risk -RiskScore $RiskScore -Points 35
                $Reasons.Add("Windows KMS host '$kmsHost' is not in the trusted KMS host list.") | Out-Null
                $Recommendations.Add('Confirm the Windows KMS host is expected for this organization.') | Out-Null
                return 'SUSPICIOUS'
            }
            $Recommendations.Add('Confirm KMS activation is expected for this device and organization.') | Out-Null
            return 'ACTIVATED_REVIEW_REQUIRED'
        }

        if ($description -match '(?i)retail' -and -not $oemKeyPresent) {
            $Reasons.Add('Windows reports Retail channel without an OEM key presence signal.') | Out-Null
            $Recommendations.Add('Confirm the Windows retail license entitlement for this device.') | Out-Null
            return 'ACTIVATED_REVIEW_REQUIRED'
        }

        return 'GENUINE_LIKELY'
    }

    if ($statusCode -eq 4 -or $statusText -match '(?i)non.?genuine') {
        Add-Risk -RiskScore $RiskScore -Points 80
        $Reasons.Add('Windows reports Non-Genuine Grace Period status.') | Out-Null
        $Recommendations.Add('Review Windows license source and activation history with an administrator.') | Out-Null
        return 'HIGH_RISK'
    }

    if ($statusCode -eq 0 -or $statusCode -eq 5 -or $statusText -match '(?i)(unlicensed|notification|not activated)') {
        Add-Risk -RiskScore $RiskScore -Points 40
        $Reasons.Add("Windows reports $statusText status.") | Out-Null
        $Recommendations.Add('Activate Windows through an approved license channel or review entitlement.') | Out-Null
        return 'NOT_ACTIVATED'
    }

    if ($statusText -match '(?i)grace') {
        Add-Risk -RiskScore $RiskScore -Points 40
        $Reasons.Add("Windows reports $statusText status.") | Out-Null
        $Recommendations.Add('Review Windows grace-period activation status before it expires.') | Out-Null
        return 'ACTIVATED_REVIEW_REQUIRED'
    }

    $Reasons.Add('Windows license status could not be confidently classified.') | Out-Null
    $Recommendations.Add('Review Windows activation details manually.') | Out-Null
    return 'NEED_MANUAL_REVIEW'
}

function Get-OfficeLicenseVerdict {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$OfficeLicense,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$TrustedKmsHosts,

        [Parameter(Mandatory)]
        [ref]$RiskScore,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Reasons,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Recommendations
    )

    if ($null -eq $OfficeLicense) {
        $Reasons.Add('Office license data is unavailable.') | Out-Null
        $Recommendations.Add('Review Office activation status manually because license collector data is unavailable.') | Out-Null
        return 'NEED_MANUAL_REVIEW'
    }

    $status = [string](Get-AuditValue -Object $OfficeLicense -Name 'Status')
    if ($status -eq 'NotDetected') {
        $Reasons.Add('Office licensing script was not detected.') | Out-Null
        return 'CLEAN'
    }

    $products = @(Get-AuditValue -Object $OfficeLicense -Name 'Products')
    if ($products.Count -eq 0) {
        $Reasons.Add('Office license products were not detected.') | Out-Null
        return 'CLEAN'
    }

    $verdict = 'GENUINE_LIKELY'
    foreach ($product in $products) {
        $productName = [string](Get-AuditValue -Object $product -Name 'ProductName')
        $licenseStatus = [string](Get-AuditValue -Object $product -Name 'LicenseStatus')
        $description = [string](Get-AuditValue -Object $product -Name 'LicenseDescriptionOrChannel')
        $kmsHost = [string](Get-AuditValue -Object $product -Name 'KmsMachineName')

        if ($licenseStatus -match '(?i)notification|notifications') {
            Add-Risk -RiskScore $RiskScore -Points 40
            $Reasons.Add("Office reports NOTIFICATIONS status for '$productName'.") | Out-Null
            $Recommendations.Add('Activate Office through an approved license channel or review entitlement.') | Out-Null
            $verdict = 'ACTIVATED_REVIEW_REQUIRED'
            continue
        }

        if ($licenseStatus -match '(?i)licensed') {
            $Reasons.Add("Office reports Licensed status for '$productName'.") | Out-Null
        }
        else {
            $Reasons.Add("Office reports '$licenseStatus' status for '$productName'.") | Out-Null
            if ($verdict -ne 'NOT_ACTIVATED') {
                $verdict = 'NEED_MANUAL_REVIEW'
            }
        }

        if (($description -match 'KMS') -or -not [string]::IsNullOrWhiteSpace($kmsHost)) {
            $Reasons.Add('KMS activation requires organization context.') | Out-Null
            if (-not (Test-TrustedKmsHost -KmsHost $kmsHost -TrustedHosts $TrustedKmsHosts)) {
                Add-Risk -RiskScore $RiskScore -Points 35
                $Reasons.Add("Office KMS host '$kmsHost' is not in the trusted KMS host list.") | Out-Null
                $Recommendations.Add('Confirm the Office KMS host is expected for this organization.') | Out-Null
                if ($verdict -eq 'GENUINE_LIKELY') {
                    $verdict = 'ACTIVATED_REVIEW_REQUIRED'
                }
            }
        }
    }

    return $verdict
}

function Get-SuspiciousIndicatorVerdict {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$SuspiciousIndicators,

        [Parameter(Mandatory)]
        [ref]$RiskScore,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Reasons,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Recommendations
    )

    if ($null -eq $SuspiciousIndicators) {
        $Reasons.Add('Suspicious indicator data is unavailable.') | Out-Null
        $Recommendations.Add('Review suspicious activation indicators manually because collector data is unavailable.') | Out-Null
        return 'NEED_MANUAL_REVIEW'
    }

    $indicators = @(Get-AuditValue -Object $SuspiciousIndicators -Name 'Indicators')
    if ($indicators.Count -eq 0) {
        $Reasons.Add('No configured suspicious activation indicators were detected.') | Out-Null
        return 'CLEAN'
    }

    $highestRisk = 0
    foreach ($indicator in $indicators) {
        $source = [string](Get-AuditValue -Object $indicator -Name 'Source')
        $evidenceType = [string](Get-AuditValue -Object $indicator -Name 'EvidenceType')
        $itemName = [string](Get-AuditValue -Object $indicator -Name 'ItemName')

        switch ($source) {
            'InstalledApplication' {
                Add-Risk -RiskScore $RiskScore -Points 25
                $highestRisk = [math]::Max($highestRisk, 25)
                $Reasons.Add("Suspicious activation-related installed application detected: '$itemName'.") | Out-Null
                break
            }
            { $_ -in @('RunningProcess', 'WindowsService', 'ScheduledTask') } {
                Add-Risk -RiskScore $RiskScore -Points 40
                $highestRisk = [math]::Max($highestRisk, 40)
                if ($source -eq 'ScheduledTask') {
                    $Reasons.Add("Suspicious activation-related scheduled task detected: '$itemName'.") | Out-Null
                }
                else {
                    $Reasons.Add("Suspicious activation-related $source detected: '$itemName'.") | Out-Null
                }
                break
            }
            'LimitedFileScan' {
                Add-Risk -RiskScore $RiskScore -Points 10
                $highestRisk = [math]::Max($highestRisk, 10)
                $Reasons.Add("Suspicious activation-related file name detected: '$itemName'.") | Out-Null
                break
            }
            default {
                $points = if ($evidenceType -eq 'FileName') { 10 } else { 25 }
                Add-Risk -RiskScore $RiskScore -Points $points
                $highestRisk = [math]::Max($highestRisk, $points)
                $Reasons.Add("Suspicious activation-related indicator detected from $source`: '$itemName'.") | Out-Null
                break
            }
        }
    }

    $Recommendations.Add('Review suspicious indicators and confirm whether each item is approved administrative tooling.') | Out-Null
    if ($highestRisk -ge 40 -or $indicators.Count -ge 3) {
        return 'HIGH_RISK'
    }

    return 'SUSPICIOUS'
}

function Get-OverallRiskVerdict {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$RiskScore,

        [Parameter(Mandatory)]
        [string]$WindowsVerdict,

        [Parameter(Mandatory)]
        [string]$OfficeVerdict,

        [Parameter(Mandatory)]
        [string]$SuspiciousIndicatorVerdict
    )

    if ($RiskScore -ge 80 -or $WindowsVerdict -eq 'HIGH_RISK' -or $SuspiciousIndicatorVerdict -eq 'HIGH_RISK') {
        return 'HIGH_RISK'
    }

    if ($WindowsVerdict -eq 'SUSPICIOUS' -or $OfficeVerdict -eq 'SUSPICIOUS' -or $SuspiciousIndicatorVerdict -eq 'SUSPICIOUS') {
        return 'SUSPICIOUS'
    }

    if ($WindowsVerdict -eq 'NOT_ACTIVATED' -or $OfficeVerdict -eq 'NOT_ACTIVATED') {
        return 'NOT_ACTIVATED'
    }

    if ($WindowsVerdict -eq 'ACTIVATED_REVIEW_REQUIRED' -or $OfficeVerdict -eq 'ACTIVATED_REVIEW_REQUIRED') {
        return 'ACTIVATED_REVIEW_REQUIRED'
    }

    if ($WindowsVerdict -eq 'NEED_MANUAL_REVIEW' -or $OfficeVerdict -eq 'NEED_MANUAL_REVIEW' -or $SuspiciousIndicatorVerdict -eq 'NEED_MANUAL_REVIEW') {
        return 'NEED_MANUAL_REVIEW'
    }

    if ($WindowsVerdict -eq 'GENUINE_LIKELY' -or $OfficeVerdict -eq 'GENUINE_LIKELY') {
        return 'GENUINE_LIKELY'
    }

    return 'CLEAN'
}

function Invoke-AuditRuleEngine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]$AuditData,

        [Parameter()]
        [switch]$IncludeSuspiciousScan
    )

    $reasons = [System.Collections.Generic.List[string]]::new()
    $recommendations = [System.Collections.Generic.List[string]]::new()
    $riskScore = 0
    $trustedKmsHosts = @(Get-TrustedKmsHosts -Reasons $reasons)

    try {
        $windowsVerdict = Get-WindowsLicenseVerdict `
            -WindowsLicense $AuditData['WindowsLicense'] `
            -TrustedKmsHosts $trustedKmsHosts `
            -RiskScore ([ref]$riskScore) `
            -Reasons $reasons `
            -Recommendations $recommendations

        $officeVerdict = Get-OfficeLicenseVerdict `
            -OfficeLicense $AuditData['OfficeLicense'] `
            -TrustedKmsHosts $trustedKmsHosts `
            -RiskScore ([ref]$riskScore) `
            -Reasons $reasons `
            -Recommendations $recommendations

        $suspiciousIndicatorVerdict = Get-SuspiciousIndicatorVerdict `
            -SuspiciousIndicators $AuditData['SuspiciousIndicators'] `
            -RiskScore ([ref]$riskScore) `
            -Reasons $reasons `
            -Recommendations $recommendations

        $overallRisk = Get-OverallRiskVerdict `
            -RiskScore $riskScore `
            -WindowsVerdict $windowsVerdict `
            -OfficeVerdict $officeVerdict `
            -SuspiciousIndicatorVerdict $suspiciousIndicatorVerdict
    }
    catch {
        $riskScore = [math]::Max($riskScore, 40)
        $windowsVerdict = 'NEED_MANUAL_REVIEW'
        $officeVerdict = 'NEED_MANUAL_REVIEW'
        $suspiciousIndicatorVerdict = 'NEED_MANUAL_REVIEW'
        $overallRisk = 'NEED_MANUAL_REVIEW'
        $reasons.Add("Rule engine failed to classify all inputs. $($_.Exception.Message)") | Out-Null
        $recommendations.Add('Review the normalized audit data manually because rule evaluation was incomplete.') | Out-Null
    }

    return [ordered]@{
        windowsVerdict             = $windowsVerdict
        officeVerdict              = $officeVerdict
        suspiciousIndicatorVerdict = $suspiciousIndicatorVerdict
        overallRisk                = $overallRisk
        riskScore                  = $riskScore
        reasons                    = @($reasons | Select-Object -Unique)
        recommendations            = @($recommendations | Select-Object -Unique)
    }
}
