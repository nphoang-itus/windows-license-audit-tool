<#
.SYNOPSIS
    Collects read-only suspicious licensing indicator metadata.

.DESCRIPTION
    Looks for configured keywords across installed applications, running
    processes, services, scheduled tasks, startup entries, and an optional
    limited file-name scan. This collector never opens file contents, deletes
    files, quarantines items, stops services, changes tasks, or modifies the
    registry.
#>

function Get-SuspiciousKeywordConfigPath {
    [CmdletBinding()]
    param()

    return (Join-Path -Path $PSScriptRoot -ChildPath '..\..\config\suspicious-keywords.json')
}

function Get-SuspiciousKeywords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    $configPath = Get-SuspiciousKeywordConfigPath
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        $Warnings.Add("Suspicious keyword config was not found: $configPath") | Out-Null
        return @()
    }

    try {
        $config = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $keywords = @()

        foreach ($entry in @($config.keywords)) {
            if ($entry -is [string]) {
                if (-not [string]::IsNullOrWhiteSpace($entry)) {
                    $keywords += [ordered]@{
                        Keyword    = $entry
                        RiskWeight = 50
                    }
                }
                continue
            }

            if ($null -ne $entry.keyword -and -not [string]::IsNullOrWhiteSpace([string]$entry.keyword)) {
                $riskWeight = 50
                if ($null -ne $entry.riskWeight) {
                    $riskWeight = [int]$entry.riskWeight
                }

                $keywords += [ordered]@{
                    Keyword    = [string]$entry.keyword
                    RiskWeight = $riskWeight
                }
            }
        }

        if ($keywords.Count -eq 0) {
            $Warnings.Add("Suspicious keyword config contains no usable keywords: $configPath") | Out-Null
        }

        return $keywords
    }
    catch {
        $Warnings.Add("Unable to load suspicious keyword config '$configPath'. $($_.Exception.Message)") | Out-Null
        return @()
    }
}

function Protect-PathUserName {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $Path
    }

    $maskedPath = $Path -replace '(?i)([A-Z]:\\Users\\)[^\\]+', '${1}<REDACTED_USER>'
    $userProfile = [Environment]::GetFolderPath('UserProfile')
    if (-not [string]::IsNullOrWhiteSpace($userProfile)) {
        $escapedProfile = [regex]::Escape($userProfile)
        $maskedProfile = ($userProfile -replace '(?i)([A-Z]:\\Users\\)[^\\]+', '${1}<REDACTED_USER>')
        $maskedPath = $maskedPath -replace $escapedProfile, $maskedProfile
    }

    return $maskedPath
}

function New-SuspiciousIndicator {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Source,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$MatchedKeyword,

        [AllowNull()]
        [string]$ItemName,

        [AllowNull()]
        [string]$ItemPath,

        [Parameter(Mandatory)]
        [int]$RiskWeight,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EvidenceType
    )

    return [ordered]@{
        Source         = $Source
        MatchedKeyword = $MatchedKeyword
        ItemName       = $ItemName
        ItemPathMasked = Protect-PathUserName -Path $ItemPath
        RiskWeight     = $RiskWeight
        EvidenceType   = $EvidenceType
    }
}

function Find-SuspiciousKeywordMatches {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Text,

        [Parameter(Mandatory)]
        [object[]]$Keywords
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return @()
    }

    $matches = @()
    foreach ($keyword in $Keywords) {
        if ($Text.IndexOf([string]$keyword.Keyword, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $matches += $keyword
        }
    }

    return $matches
}

function Get-SuspiciousObjectPropertyValue {
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

    $property = $Object.PSObject.Properties[$Name]
    if ($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Add-SuspiciousMatchesForItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Indicators,

        [Parameter(Mandatory)]
        [object[]]$Keywords,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Source,

        [AllowNull()]
        [string]$ItemName,

        [AllowNull()]
        [string]$ItemPath,

        [AllowNull()]
        [string]$SearchText,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EvidenceType
    )

    foreach ($match in (Find-SuspiciousKeywordMatches -Text $SearchText -Keywords $Keywords)) {
        $Indicators.Add((New-SuspiciousIndicator `
            -Source $Source `
            -MatchedKeyword $match.Keyword `
            -ItemName $ItemName `
            -ItemPath $ItemPath `
            -RiskWeight $match.RiskWeight `
            -EvidenceType $EvidenceType)) | Out-Null
    }
}

function Add-InstalledApplicationIndicators {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Indicators,

        [Parameter(Mandatory)]
        [object[]]$Keywords,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($registryPath in $registryPaths) {
        $queryErrors = @()
        $applications = @(Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue -ErrorVariable queryErrors)
        foreach ($queryError in $queryErrors) {
            $Warnings.Add("Unable to read installed application registry path '$registryPath'. $($queryError.Exception.Message)") | Out-Null
        }

        foreach ($application in $applications) {
            $name = [string](Get-SuspiciousObjectPropertyValue -Object $application -Name 'DisplayName')
            $path = [string](Get-SuspiciousObjectPropertyValue -Object $application -Name 'InstallLocation')
            if ([string]::IsNullOrWhiteSpace($path)) {
                $path = [string](Get-SuspiciousObjectPropertyValue -Object $application -Name 'PSPath')
            }

            $searchText = @(
                (Get-SuspiciousObjectPropertyValue -Object $application -Name 'DisplayName'),
                (Get-SuspiciousObjectPropertyValue -Object $application -Name 'DisplayVersion'),
                (Get-SuspiciousObjectPropertyValue -Object $application -Name 'Publisher'),
                (Get-SuspiciousObjectPropertyValue -Object $application -Name 'InstallLocation'),
                (Get-SuspiciousObjectPropertyValue -Object $application -Name 'UninstallString')
            ) -join ' '

            Add-SuspiciousMatchesForItem -Indicators $Indicators -Keywords $Keywords -Source 'InstalledApplication' -ItemName $name -ItemPath $path -SearchText $searchText -EvidenceType 'RegistryUninstallEntry'
        }
    }
}

function Add-ProcessIndicators {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Indicators,

        [Parameter(Mandatory)]
        [object[]]$Keywords,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    try {
        foreach ($process in @(Get-Process -ErrorAction Stop)) {
            $path = $null
            try {
                $path = $process.Path
            }
            catch {
                $Warnings.Add("Unable to read process path for '$($process.ProcessName)'. $($_.Exception.Message)") | Out-Null
            }

            $searchText = @($process.ProcessName, $path) -join ' '
            Add-SuspiciousMatchesForItem -Indicators $Indicators -Keywords $Keywords -Source 'RunningProcess' -ItemName $process.ProcessName -ItemPath $path -SearchText $searchText -EvidenceType 'Process'
        }
    }
    catch {
        $Warnings.Add("Unable to enumerate running processes. $($_.Exception.Message)") | Out-Null
    }
}

function Add-ServiceIndicators {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Indicators,

        [Parameter(Mandatory)]
        [object[]]$Keywords,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    try {
        foreach ($service in @(Get-CimInstance -ClassName 'Win32_Service' -ErrorAction Stop)) {
            $searchText = @($service.Name, $service.DisplayName, $service.Description, $service.PathName) -join ' '
            Add-SuspiciousMatchesForItem -Indicators $Indicators -Keywords $Keywords -Source 'WindowsService' -ItemName $service.DisplayName -ItemPath $service.PathName -SearchText $searchText -EvidenceType 'Service'
        }
    }
    catch {
        $Warnings.Add("Unable to enumerate Windows services. $($_.Exception.Message)") | Out-Null
    }
}

function Add-ScheduledTaskIndicators {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Indicators,

        [Parameter(Mandatory)]
        [object[]]$Keywords,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
            $actions = @($task.Actions | ForEach-Object { @($_.Execute, $_.Arguments) -join ' ' }) -join ' '
            $taskPath = "$($task.TaskPath)$($task.TaskName)"
            $searchText = @($task.TaskName, $task.TaskPath, $actions) -join ' '
            Add-SuspiciousMatchesForItem -Indicators $Indicators -Keywords $Keywords -Source 'ScheduledTask' -ItemName $task.TaskName -ItemPath $taskPath -SearchText $searchText -EvidenceType 'ScheduledTask'
        }
    }
    catch {
        $Warnings.Add("Unable to enumerate scheduled tasks. $($_.Exception.Message)") | Out-Null
    }
}

function Add-StartupEntryIndicators {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Indicators,

        [Parameter(Mandatory)]
        [object[]]$Keywords,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings
    )

    $runKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($runKey in $runKeys) {
        if (-not (Test-Path -LiteralPath $runKey)) {
            continue
        }

        $queryErrors = @()
        $entry = Get-ItemProperty -LiteralPath $runKey -ErrorAction SilentlyContinue -ErrorVariable queryErrors
        foreach ($queryError in $queryErrors) {
            $Warnings.Add("Unable to read startup registry key '$runKey'. $($queryError.Exception.Message)") | Out-Null
        }

        if ($null -eq $entry) {
            continue
        }

        foreach ($property in $entry.PSObject.Properties) {
            if ($property.Name -like 'PS*') {
                continue
            }

            $searchText = @($property.Name, $property.Value) -join ' '
            Add-SuspiciousMatchesForItem -Indicators $Indicators -Keywords $Keywords -Source 'StartupEntry' -ItemName $property.Name -ItemPath ([string]$property.Value) -SearchText $searchText -EvidenceType 'RegistryRunEntry'
        }
    }
}

function Get-LimitedSuspiciousFileScanRoots {
    [CmdletBinding()]
    param()

    $roots = @('C:\ProgramData')
    $userProfile = [Environment]::GetFolderPath('UserProfile')

    foreach ($folderName in @('DesktopDirectory', 'LocalApplicationData', 'ApplicationData')) {
        $folderPath = [Environment]::GetFolderPath($folderName)
        if (-not [string]::IsNullOrWhiteSpace($folderPath)) {
            $roots += $folderPath
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($userProfile)) {
        $roots += (Join-Path -Path $userProfile -ChildPath 'Downloads')
    }

    return @($roots | Select-Object -Unique)
}

function Add-LimitedFileIndicators {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList]$Indicators,

        [Parameter(Mandatory)]
        [object[]]$Keywords,

        [Parameter(Mandatory)]
        [System.Collections.IList]$Warnings,

        [Parameter()]
        [int]$MaxDepth = 2,

        [Parameter()]
        [int]$MaxItemsPerRoot = 500
    )

    foreach ($root in (Get-LimitedSuspiciousFileScanRoots)) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) {
            continue
        }

        $scanErrors = @()
        $items = @(Get-ChildItem -LiteralPath $root -File -Recurse -Depth $MaxDepth -ErrorAction SilentlyContinue -ErrorVariable scanErrors | Select-Object -First $MaxItemsPerRoot)
        foreach ($scanError in $scanErrors) {
            $Warnings.Add("Unable to scan file path under '$root'. $($scanError.Exception.Message)") | Out-Null
        }

        foreach ($item in $items) {
            $searchText = @($item.Name, $item.FullName) -join ' '
            Add-SuspiciousMatchesForItem -Indicators $Indicators -Keywords $Keywords -Source 'LimitedFileScan' -ItemName $item.Name -ItemPath $item.FullName -SearchText $searchText -EvidenceType 'FileName'
        }
    }
}

function Get-SuspiciousIndicatorAuditInfo {
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$SkipDeepScan
    )

    $warnings = [System.Collections.Generic.List[string]]::new()
    $indicators = [System.Collections.Generic.List[object]]::new()
    $keywords = @(Get-SuspiciousKeywords -Warnings $warnings)

    if ($keywords.Count -gt 0) {
        Add-InstalledApplicationIndicators -Indicators $indicators -Keywords $keywords -Warnings $warnings
        Add-ProcessIndicators -Indicators $indicators -Keywords $keywords -Warnings $warnings
        Add-ServiceIndicators -Indicators $indicators -Keywords $keywords -Warnings $warnings
        Add-ScheduledTaskIndicators -Indicators $indicators -Keywords $keywords -Warnings $warnings
        Add-StartupEntryIndicators -Indicators $indicators -Keywords $keywords -Warnings $warnings

        if (-not $SkipDeepScan) {
            Add-LimitedFileIndicators -Indicators $indicators -Keywords $keywords -Warnings $warnings
        }
    }

    return [ordered]@{
        CollectorName      = 'SuspiciousIndicators'
        Status             = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }
        DeepScanRequested  = -not [bool]$SkipDeepScan
        FileScanPerformed  = (-not [bool]$SkipDeepScan) -and $keywords.Count -gt 0
        FileScanRoots      = if ($SkipDeepScan) { @() } else { Get-LimitedSuspiciousFileScanRoots }
        FileScanMaxDepth   = if ($SkipDeepScan) { 0 } else { 2 }
        KeywordsLoaded     = $keywords.Count
        Indicators         = @($indicators)
        Warnings           = @($warnings)
    }
}
