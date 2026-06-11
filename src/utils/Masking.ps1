<#
.SYNOPSIS
    Masks sensitive values before report export.

.DESCRIPTION
    Provides placeholder-safe masking for serial numbers, MAC addresses, usernames,
    product keys, and similar sensitive fields. This module only transforms in-memory
    report objects and never modifies source system data.
#>

function Protect-SensitiveValue {
    <#
    .SYNOPSIS
        Returns a masked representation of a sensitive scalar value.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $text
    }

    if ($text.Length -le 4) {
        return '****'
    }

    return ('****' + $text.Substring($text.Length - 4))
}

function Protect-AuditReportSensitiveData {
    <#
    .SYNOPSIS
        Recursively masks sensitive properties in the normalized audit report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object]$InputObject
    )

    $sensitiveNamePattern = '(?i)(serial|mac|user(name)?|product.?key|partial.?key|key|sid)'

    if ($InputObject -is [System.Collections.IDictionary]) {
        $masked = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            if ($key -match $sensitiveNamePattern) {
                $masked[$key] = Protect-SensitiveValue -Value $InputObject[$key]
            }
            else {
                $masked[$key] = Protect-AuditReportSensitiveData -InputObject $InputObject[$key]
            }
        }
        return $masked
    }

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $items = @()
        foreach ($item in $InputObject) {
            $items += Protect-AuditReportSensitiveData -InputObject $item
        }
        return $items
    }

    return $InputObject
}
