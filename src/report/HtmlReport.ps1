<#
.SYNOPSIS
    Exports normalized audit data as an administrative-style HTML report.

.DESCRIPTION
    Renders an A4, Times New Roman report from the already-masked normalized
    audit report object. The renderer escapes all inserted values and does not
    include raw diagnostics, full product keys, or unmasked serial numbers.
#>

function ConvertTo-HtmlEscapedText {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-ReportValue {
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

function Format-ReportScalar {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 'N/A'
    }

    if ($Value -is [bool]) {
        if ($Value) {
            return 'Yes'
        }
        return 'No'
    }

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @()
        foreach ($item in $Value) {
            if ($null -ne $item -and -not [string]::IsNullOrWhiteSpace([string]$item)) {
                $items += [string]$item
            }
        }

        if ($items.Count -eq 0) {
            return 'N/A'
        }

        return ($items -join ', ')
    }

    if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        return 'N/A'
    }

    return [string]$Value
}

function New-ReportTableRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Label,

        [AllowNull()]
        [object]$Value
    )

    $safeLabel = $Label
    $safeValue = ConvertTo-HtmlEscapedText -Value (Format-ReportScalar -Value $Value)
    return "<tr><th>$safeLabel</th><td>$safeValue</td></tr>"
}

function New-ReportDataRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Values
    )

    $cells = @()
    foreach ($value in $Values) {
        $cells += ('<td>{0}</td>' -f (ConvertTo-HtmlEscapedText -Value (Format-ReportScalar -Value $value)))
    }

    return ('<tr>{0}</tr>' -f ($cells -join ''))
}

function Get-ReportRiskCssClass {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Verdict
    )

    switch -Regex ($Verdict) {
        '^(CLEAN|GENUINE_LIKELY)$' { return 'risk-normal' }
        '^(ACTIVATED_REVIEW_REQUIRED|REVIEW_REQUIRED|SUSPICIOUS|NOT_ACTIVATED|NEED_MANUAL_REVIEW)$' { return 'risk-warning' }
        '^HIGH_RISK$' { return 'risk-high' }
        default { return 'risk-warning' }
    }
}

function Get-ReportCautiousAssessment {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$OverallRisk
    )

    switch -Regex ($OverallRisk) {
        '^(CLEAN|GENUINE_LIKELY)$' {
            return 'Ch&#432;a ghi nh&#7853;n d&#7845;u hi&#7879;u b&#7845;t th&#432;&#7901;ng r&#245; r&#224;ng t&#7915; c&#225;c ngu&#7891;n d&#7919; li&#7879;u &#273;&#227; thu th&#7853;p. Kh&#244;ng &#273;&#7911; b&#7857;ng ch&#7913;ng &#273;&#7875; k&#7871;t lu&#7853;n tuy&#7879;t &#273;&#7889;i.'
        }
        '^(ACTIVATED_REVIEW_REQUIRED|REVIEW_REQUIRED|SUSPICIOUS|NOT_ACTIVATED|NEED_MANUAL_REVIEW)$' {
            return 'C&#243; d&#7845;u hi&#7879;u nghi v&#7845;n ho&#7863;c c&#7847;n b&#7893; sung ng&#7919; c&#7843;nh qu&#7843;n tr&#7883;. C&#7847;n ki&#7875;m tra th&#7911; c&#244;ng. Kh&#244;ng &#273;&#7911; b&#7857;ng ch&#7913;ng &#273;&#7875; k&#7871;t lu&#7853;n tuy&#7879;t &#273;&#7889;i.'
        }
        '^HIGH_RISK$' {
            return 'C&#243; d&#7845;u hi&#7879;u nghi v&#7845;n v&#7899;i m&#7913;c r&#7911;i ro cao theo c&#225;c b&#7857;ng ch&#7913;ng &#273;&#227; thu th&#7853;p. C&#7847;n ki&#7875;m tra th&#7911; c&#244;ng. Kh&#244;ng &#273;&#7911; b&#7857;ng ch&#7913;ng &#273;&#7875; k&#7871;t lu&#7853;n tuy&#7879;t &#273;&#7889;i.'
        }
        default {
            return 'C&#7847;n ki&#7875;m tra th&#7911; c&#244;ng. Kh&#244;ng &#273;&#7911; b&#7857;ng ch&#7913;ng &#273;&#7875; k&#7871;t lu&#7853;n tuy&#7879;t &#273;&#7889;i.'
        }
    }
}

function ConvertTo-VietnameseVerdictHtml {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Verdict
    )

    switch ($Verdict) {
        'CLEAN' { return 'B&#236;nh th&#432;&#7901;ng (CLEAN)' }
        'GENUINE_LIKELY' { return 'C&#243; kh&#7843; n&#259;ng h&#7907;p l&#7879; (GENUINE_LIKELY)' }
        'GENUINE_LIKELY_FOR_ORG' { return 'C&#243; kh&#7843; n&#259;ng h&#7907;p l&#7879; trong m&#244;i tr&#432;&#7901;ng t&#7893; ch&#7913;c (GENUINE_LIKELY_FOR_ORG)' }
        'ACTIVATED_REVIEW_REQUIRED' { return '&#272;&#227; k&#237;ch ho&#7841;t nh&#432;ng c&#7847;n ki&#7875;m tra th&#7911; c&#244;ng (ACTIVATED_REVIEW_REQUIRED)' }
        'NOT_ACTIVATED' { return 'Ch&#432;a k&#237;ch ho&#7841;t ho&#7863;c &#273;ang &#7903; tr&#7841;ng th&#225;i th&#244;ng b&#225;o (NOT_ACTIVATED)' }
        'SUSPICIOUS' { return 'C&#243; d&#7845;u hi&#7879;u nghi v&#7845;n (SUSPICIOUS)' }
        'HIGH_RISK' { return 'R&#7911;i ro cao, c&#7847;n ki&#7875;m tra ngay (HIGH_RISK)' }
        'NEED_MANUAL_REVIEW' { return 'C&#7847;n ki&#7875;m tra th&#7911; c&#244;ng (NEED_MANUAL_REVIEW)' }
        default {
            if ([string]::IsNullOrWhiteSpace($Verdict)) {
                return 'N/A'
            }
            return ConvertTo-HtmlEscapedText -Value $Verdict
        }
    }
}

function ConvertTo-VietnameseRuleTextHtml {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return 'N/A'
    }

    switch -Regex ($Text) {
        '^Windows reports Licensed status\.$' {
            return 'Windows b&#225;o tr&#7841;ng th&#225;i &#273;&#227; k&#237;ch ho&#7841;t.'
        }
        '^Windows reports Retail channel without an OEM key presence signal\.$' {
            return 'Windows b&#225;o k&#234;nh Retail nh&#432;ng kh&#244;ng c&#243; t&#237;n hi&#7879;u OEM key; c&#7847;n &#273;&#7889;i chi&#7871;u l&#7841;i quy&#7873;n s&#7917; d&#7909;ng.'
        }
        '^KMS activation requires organization context\.$' {
            return 'K&#237;ch ho&#7841;t KMS c&#7847;n ng&#7919; c&#7843;nh c&#7911;a t&#7893; ch&#7913;c.'
        }
        '^Windows KMS host ''(.+)'' is not in the trusted KMS host list\.$' {
            return ('KMS host Windows ''{0}'' kh&#244;ng n&#7857;m trong danh s&#225;ch tin c&#7853;y.' -f (ConvertTo-HtmlEscapedText -Value $Matches[1]))
        }
        '^Windows reports Non-Genuine Grace Period status\.$' {
            return 'Windows b&#225;o tr&#7841;ng th&#225;i Non-Genuine Grace Period.'
        }
        '^Windows reports (.+) status\.$' {
            return ('Windows b&#225;o tr&#7841;ng th&#225;i: {0}.' -f (ConvertTo-HtmlEscapedText -Value $Matches[1]))
        }
        '^Office licensing script was not detected\.$' {
            return 'Kh&#244;ng ph&#225;t hi&#7879;n script ki&#7875;m tra license Office.'
        }
        '^Office license products were not detected\.$' {
            return 'Kh&#244;ng ph&#225;t hi&#7879;n s&#7843;n ph&#7849;m license Office.'
        }
        '^Office reports Licensed status for ''(.+)''\.$' {
            return ('Office b&#225;o &#273;&#227; k&#237;ch ho&#7841;t cho ''{0}''.' -f (ConvertTo-HtmlEscapedText -Value $Matches[1]))
        }
        '^Office reports NOTIFICATIONS status for ''(.+)''\.$' {
            return ('Office b&#225;o tr&#7841;ng th&#225;i NOTIFICATIONS cho ''{0}''.' -f (ConvertTo-HtmlEscapedText -Value $Matches[1]))
        }
        '^Office KMS host ''(.+)'' is not in the trusted KMS host list\.$' {
            return ('KMS host Office ''{0}'' kh&#244;ng n&#7857;m trong danh s&#225;ch tin c&#7853;y.' -f (ConvertTo-HtmlEscapedText -Value $Matches[1]))
        }
        '^No configured suspicious activation indicators were detected\.$' {
            return 'Kh&#244;ng ph&#225;t hi&#7879;n ch&#7881; b&#225;o nghi v&#7845;n theo danh s&#225;ch t&#7915; kh&#243;a &#273;&#227; c&#7845;u h&#236;nh.'
        }
        '^Suspicious activation-related scheduled task detected: ''(.+)''\.$' {
            return ('Ph&#225;t hi&#7879;n scheduled task c&#243; d&#7845;u hi&#7879;u li&#234;n quan k&#237;ch ho&#7841;t: ''{0}''.' -f (ConvertTo-HtmlEscapedText -Value $Matches[1]))
        }
        '^Suspicious activation-related file name detected: ''(.+)''\.$' {
            return ('Ph&#225;t hi&#7879;n t&#234;n file c&#243; d&#7845;u hi&#7879;u li&#234;n quan k&#237;ch ho&#7841;t: ''{0}''.' -f (ConvertTo-HtmlEscapedText -Value $Matches[1]))
        }
        '^Suspicious activation-related installed application detected: ''(.+)''\.$' {
            return ('Ph&#225;t hi&#7879;n &#7913;ng d&#7909;ng c&#224;i &#273;&#7863;t c&#243; d&#7845;u hi&#7879;u li&#234;n quan k&#237;ch ho&#7841;t: ''{0}''.' -f (ConvertTo-HtmlEscapedText -Value $Matches[1]))
        }
        '^Activate Windows through an approved license channel or review entitlement\.$' {
            return 'K&#237;ch ho&#7841;t Windows qua k&#234;nh license &#273;&#432;&#7907;c ph&#234; duy&#7879;t ho&#7863;c ki&#7875;m tra l&#7841;i quy&#7873;n s&#7917; d&#7909;ng.'
        }
        '^Activate Office through an approved license channel or review entitlement\.$' {
            return 'K&#237;ch ho&#7841;t Office qua k&#234;nh license &#273;&#432;&#7907;c ph&#234; duy&#7879;t ho&#7863;c ki&#7875;m tra l&#7841;i quy&#7873;n s&#7917; d&#7909;ng.'
        }
        '^Confirm the Windows retail license entitlement for this device\.$' {
            return 'X&#225;c nh&#7853;n quy&#7873;n s&#7917; d&#7909;ng license Retail c&#7911;a Windows tr&#234;n m&#225;y n&#224;y.'
        }
        '^Confirm the Windows KMS host is expected for this organization\.$' {
            return 'X&#225;c nh&#7853;n KMS host Windows c&#243; &#273;&#250;ng l&#224; h&#7879; th&#7889;ng c&#7911;a t&#7893; ch&#7913;c hay kh&#244;ng.'
        }
        '^Confirm KMS activation is expected for this device and organization\.$' {
            return 'X&#225;c nh&#7853;n vi&#7879;c k&#237;ch ho&#7841;t KMS l&#224; ph&#249; h&#7907;p v&#7899;i m&#225;y v&#224; t&#7893; ch&#7913;c.'
        }
        '^Review suspicious indicators and confirm whether each item is approved administrative tooling\.$' {
            return 'Ki&#7875;m tra th&#7911; c&#244;ng c&#225;c ch&#7881; b&#225;o nghi v&#7845;n v&#224; x&#225;c nh&#7853;n ch&#250;ng c&#243; ph&#7843;i c&#244;ng c&#7909; qu&#7843;n tr&#7883; &#273;&#432;&#7907;c ph&#234; duy&#7879;t hay kh&#244;ng.'
        }
        default {
            return ConvertTo-HtmlEscapedText -Value $Text
        }
    }
}

function Get-ReportExtractionTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AuditReport
    )

    $system = Get-ReportValue -Object $AuditReport -Name 'System'
    $extractionTime = Get-ReportValue -Object $system -Name 'ExtractionTimeUtc'
    if ($null -eq $extractionTime) {
        $extractionTime = Get-ReportValue -Object $AuditReport -Name 'GeneratedAtUtc'
    }

    return $extractionTime
}

function New-HardwareFingerprintRows {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Hardware
    )

    $motherboard = Get-ReportValue -Object $Hardware -Name 'Motherboard'
    $disks = @(Get-ReportValue -Object $Hardware -Name 'PhysicalDisks')
    $diskText = if ($disks.Count -gt 0) {
        (($disks | ForEach-Object {
            '{0} / {1}' -f (Format-ReportScalar -Value (Get-ReportValue -Object $_ -Name 'Model')), (Format-ReportScalar -Value (Get-ReportValue -Object $_ -Name 'SerialNumber'))
        }) -join '; ')
    }
    else {
        $null
    }

    return @(
        New-ReportTableRow -Label 'H&#227;ng s&#7843;n xu&#7845;t' -Value (Get-ReportValue -Object $Hardware -Name 'Manufacturer')
        New-ReportTableRow -Label 'Model' -Value (Get-ReportValue -Object $Hardware -Name 'Model')
        New-ReportTableRow -Label 'CPU' -Value (Get-ReportValue -Object $Hardware -Name 'CpuName')
        New-ReportTableRow -Label 'T&#7893;ng RAM (GB)' -Value (Get-ReportValue -Object $Hardware -Name 'TotalRamGb')
        New-ReportTableRow -Label 'H&#227;ng mainboard' -Value (Get-ReportValue -Object $motherboard -Name 'Manufacturer')
        New-ReportTableRow -Label 'M&#227; mainboard' -Value (Get-ReportValue -Object $motherboard -Name 'Product')
        New-ReportTableRow -Label 'Serial mainboard' -Value (Get-ReportValue -Object $motherboard -Name 'SerialNumber')
        New-ReportTableRow -Label 'Serial BIOS' -Value (Get-ReportValue -Object $Hardware -Name 'BiosSerialNumber')
        New-ReportTableRow -Label '&#7892; &#273;&#297;a v&#7853;t l&#253;' -Value $diskText
        New-ReportTableRow -Label '&#272;&#7883;a ch&#7881; MAC &#273;ang ho&#7841;t &#273;&#7897;ng' -Value (Get-ReportValue -Object $Hardware -Name 'ActiveMacAddresses')
    ) -join [Environment]::NewLine
}

function New-WindowsLicenseRows {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$WindowsLicense
    )

    return @(
        New-ReportTableRow -Label 'T&#234;n Windows' -Value (Get-ReportValue -Object $WindowsLicense -Name 'WindowsCaption')
        New-ReportTableRow -Label 'Phi&#234;n b&#7843;n' -Value (Get-ReportValue -Object $WindowsLicense -Name 'Version')
        New-ReportTableRow -Label 'Build number' -Value (Get-ReportValue -Object $WindowsLicense -Name 'BuildNumber')
        New-ReportTableRow -Label 'Ki&#7871;n tr&#250;c' -Value (Get-ReportValue -Object $WindowsLicense -Name 'Architecture')
        New-ReportTableRow -Label 'Product ID' -Value (Get-ReportValue -Object $WindowsLicense -Name 'ProductId')
        New-ReportTableRow -Label 'T&#234;n license' -Value (Get-ReportValue -Object $WindowsLicense -Name 'LicenseName')
        New-ReportTableRow -Label 'M&#244; t&#7843; license' -Value (Get-ReportValue -Object $WindowsLicense -Name 'LicenseDescription')
        New-ReportTableRow -Label 'Tr&#7841;ng th&#225;i license' -Value (Get-ReportValue -Object $WindowsLicense -Name 'LicenseStatusText')
        New-ReportTableRow -Label 'Partial product key' -Value (Get-ReportValue -Object $WindowsLicense -Name 'PartialProductKey')
        New-ReportTableRow -Label 'C&#243; OEM key' -Value (Get-ReportValue -Object $WindowsLicense -Name 'OemKeyPresent')
        New-ReportTableRow -Label 'KMS host' -Value (Get-ReportValue -Object $WindowsLicense -Name 'KmsHost')
        New-ReportTableRow -Label 'KMS port' -Value (Get-ReportValue -Object $WindowsLicense -Name 'KmsPort')
    ) -join [Environment]::NewLine
}

function New-OfficeLicenseRows {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$OfficeLicense
    )

    $products = @(Get-ReportValue -Object $OfficeLicense -Name 'Products')
    if ($products.Count -eq 0) {
        return (New-ReportDataRow -Values @(
            (Get-ReportValue -Object $OfficeLicense -Name 'Status'),
            'N/A',
            'N/A',
            'N/A',
            'N/A',
            'N/A'
        ))
    }

    $rows = @()
    foreach ($product in $products) {
        $rows += New-ReportDataRow -Values @(
            (Get-ReportValue -Object $product -Name 'ProductName'),
            (Get-ReportValue -Object $product -Name 'LicenseName'),
            (Get-ReportValue -Object $product -Name 'LicenseDescriptionOrChannel'),
            (Get-ReportValue -Object $product -Name 'LicenseStatus'),
            (Get-ReportValue -Object $product -Name 'InstalledProductKeyLast5'),
            (Get-ReportValue -Object $product -Name 'KmsMachineName')
        )
    }

    return ($rows -join [Environment]::NewLine)
}

function New-CommentListItems {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object[]]$Values
    )

    $items = @()
    foreach ($value in @($Values)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) {
            $items += ('<li>{0}</li>' -f (ConvertTo-VietnameseRuleTextHtml -Text ([string]$value)))
        }
    }

    if ($items.Count -eq 0) {
        return '<li>N/A</li>'
    }

    return ($items -join [Environment]::NewLine)
}

function ConvertTo-AuditHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$AuditReport,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TemplatePath
    )

    if (-not (Test-Path -LiteralPath $TemplatePath -PathType Leaf)) {
        throw "HTML report template was not found: $TemplatePath"
    }

    $template = Get-Content -LiteralPath $TemplatePath -Raw -ErrorAction Stop
    $system = Get-ReportValue -Object $AuditReport -Name 'System'
    $hardware = Get-ReportValue -Object $AuditReport -Name 'Hardware'
    $windowsLicense = Get-ReportValue -Object $AuditReport -Name 'WindowsLicense'
    $officeLicense = Get-ReportValue -Object $AuditReport -Name 'OfficeLicense'
    $rules = Get-ReportValue -Object $AuditReport -Name 'Rules'

    $overallRisk = [string](Get-ReportValue -Object $rules -Name 'overallRisk')
    $riskCssClass = Get-ReportRiskCssClass -Verdict $overallRisk
    $assessment = Get-ReportCautiousAssessment -OverallRisk $overallRisk

    $tokens = @{
        '{{TITLE}}' = 'BI&#202;N B&#7842;N TR&#205;CH XU&#7844;T TH&#212;NG TIN B&#7842;N QUY&#7872;N M&#193;Y T&#205;NH'
        '{{EXTRACTION_TIME}}' = ConvertTo-HtmlEscapedText -Value (Format-ReportScalar -Value (Get-ReportExtractionTime -AuditReport $AuditReport))
        '{{PC_NAME}}' = ConvertTo-HtmlEscapedText -Value (Format-ReportScalar -Value (Get-ReportValue -Object $system -Name 'ComputerName'))
        '{{LOGGED_IN_ACCOUNT}}' = ConvertTo-HtmlEscapedText -Value (Format-ReportScalar -Value (Get-ReportValue -Object $system -Name 'LoggedInUser'))
        '{{DOMAIN_OR_WORKGROUP}}' = ConvertTo-HtmlEscapedText -Value (Format-ReportScalar -Value (Get-ReportValue -Object $system -Name 'DomainOrWorkgroup'))
        '{{HARDWARE_ROWS}}' = New-HardwareFingerprintRows -Hardware $hardware
        '{{WINDOWS_ROWS}}' = New-WindowsLicenseRows -WindowsLicense $windowsLicense
        '{{OFFICE_ROWS}}' = New-OfficeLicenseRows -OfficeLicense $officeLicense
        '{{RISK_CLASS}}' = ConvertTo-HtmlEscapedText -Value $riskCssClass
        '{{OVERALL_RISK}}' = ConvertTo-VietnameseVerdictHtml -Verdict $overallRisk
        '{{WINDOWS_VERDICT}}' = ConvertTo-VietnameseVerdictHtml -Verdict ([string](Get-ReportValue -Object $rules -Name 'windowsVerdict'))
        '{{OFFICE_VERDICT}}' = ConvertTo-VietnameseVerdictHtml -Verdict ([string](Get-ReportValue -Object $rules -Name 'officeVerdict'))
        '{{SUSPICIOUS_VERDICT}}' = ConvertTo-VietnameseVerdictHtml -Verdict ([string](Get-ReportValue -Object $rules -Name 'suspiciousIndicatorVerdict'))
        '{{RISK_SCORE}}' = ConvertTo-HtmlEscapedText -Value (Format-ReportScalar -Value (Get-ReportValue -Object $rules -Name 'riskScore'))
        '{{CAUTIOUS_ASSESSMENT}}' = $assessment
        '{{REASONS}}' = New-CommentListItems -Values @(Get-ReportValue -Object $rules -Name 'reasons')
        '{{RECOMMENDATIONS}}' = New-CommentListItems -Values @(Get-ReportValue -Object $rules -Name 'recommendations')
    }

    foreach ($token in $tokens.Keys) {
        $template = $template.Replace($token, [string]$tokens[$token])
    }

    return $template
}

function Export-AuditHtmlReport {
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
        $fileName = "windows-license-audit-$timestamp.html"
        $htmlPath = Join-Path -Path $resolvedOutputDir -ChildPath $fileName
        $templatePath = Join-Path -Path $PSScriptRoot -ChildPath 'templates\report.template.html'
        $html = ConvertTo-AuditHtmlReport -AuditReport $AuditReport -TemplatePath $templatePath

        Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
        return $htmlPath
    }
    catch {
        throw "Unable to export HTML report. $($_.Exception.Message)"
    }
}
