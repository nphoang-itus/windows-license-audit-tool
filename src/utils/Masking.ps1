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

    return Protect-SerialNumber -Value $Value
}

function Protect-UserName {
    <#
    .SYNOPSIS
        Redacts usernames with a stable placeholder.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        return [string]$Value
    }

    return '<REDACTED_USER>'
}

function Protect-MacAddress {
    <#
    .SYNOPSIS
        Masks middle MAC address bytes while preserving the vendor and final byte.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $text
    }

    $separator = if ($text -match '-') { '-' } else { ':' }
    $parts = $text -split '[:-]'
    if ($parts.Count -ne 6) {
        return Protect-SerialNumber -Value $text
    }

    return ($parts[0], $parts[1], 'XX', 'XX', 'XX', $parts[5]) -join $separator
}

function Protect-SerialNumber {
    <#
    .SYNOPSIS
        Preserves the first three and last four characters of serial-like values.
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

    if ($text.Length -le 7) {
        return ('*' * $text.Length)
    }

    return ('{0}****{1}' -f $text.Substring(0, 3), $text.Substring($text.Length - 4))
}

function Protect-SensitiveValueOrCollection {
    <#
    .SYNOPSIS
        Applies a scalar masking function to a scalar or every item in a collection.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory)]
        [scriptblock]$Masker
    )

    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $items = @()
        foreach ($item in $Value) {
            $items += & $Masker $item
        }
        return ,$items
    }

    return & $Masker $Value
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

    $serialNamePattern = '(?i)(serial|product.?key|partial.?key|key|sid)'
    $macNamePattern = '(?i)mac'
    $userNamePattern = '(?i)user(name)?'

    if ($InputObject -is [System.Collections.IDictionary]) {
        $masked = [ordered]@{}
        foreach ($key in $InputObject.Keys) {
            if ($key -match '(?i)^(PartialProductKey|InstalledProductKeyLast5)$') {
                $masked[$key] = $InputObject[$key]
            }
            elseif ($key -match $userNamePattern) {
                $masked[$key] = Protect-SensitiveValueOrCollection -Value $InputObject[$key] -Masker ${function:Protect-UserName}
            }
            elseif ($key -match $macNamePattern) {
                $masked[$key] = Protect-SensitiveValueOrCollection -Value $InputObject[$key] -Masker ${function:Protect-MacAddress}
            }
            elseif ($key -match $serialNamePattern) {
                $masked[$key] = Protect-SensitiveValueOrCollection -Value $InputObject[$key] -Masker ${function:Protect-SerialNumber}
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
