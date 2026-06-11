<#
.SYNOPSIS
    Collects read-only operating system and environment metadata.

.DESCRIPTION
    Uses CIM read queries for system facts such as OS name, version, build, install
    date, computer name, logged-in user, and domain/workgroup. Query failures are
    recorded as warnings so a partial report can still be generated.
#>

function Invoke-SystemCimQuery {
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

function Get-SystemAuditInfo {
    [CmdletBinding()]
    param()

    $warnings = [System.Collections.Generic.List[string]]::new()
    $os = Invoke-SystemCimQuery -ClassName 'Win32_OperatingSystem' -Warnings $warnings
    $computerSystem = Invoke-SystemCimQuery -ClassName 'Win32_ComputerSystem' -Warnings $warnings

    $loggedInUser = $null
    $domainOrWorkgroup = $null

    if ($null -ne $computerSystem) {
        $loggedInUser = $computerSystem.UserName

        if ($computerSystem.PartOfDomain -and -not [string]::IsNullOrWhiteSpace($computerSystem.Domain)) {
            $domainOrWorkgroup = $computerSystem.Domain
        }
        elseif (-not [string]::IsNullOrWhiteSpace($computerSystem.Workgroup)) {
            $domainOrWorkgroup = $computerSystem.Workgroup
        }
    }

    return [ordered]@{
        CollectorName     = 'System'
        Status            = if ($warnings.Count -gt 0) { 'Partial' } else { 'Complete' }
        ExtractionTimeUtc = (Get-Date).ToUniversalTime().ToString('o')
        ComputerName      = if ($null -ne $os -and -not [string]::IsNullOrWhiteSpace($os.CSName)) { $os.CSName } else { $env:COMPUTERNAME }
        LoggedInUser      = $loggedInUser
        DomainOrWorkgroup = $domainOrWorkgroup
        OsCaption         = if ($null -ne $os) { $os.Caption } else { $null }
        OsVersion         = if ($null -ne $os) { $os.Version } else { $null }
        BuildNumber       = if ($null -ne $os) { $os.BuildNumber } else { $null }
        Architecture      = if ($null -ne $os) { $os.OSArchitecture } else { $null }
        InstallDate       = if ($null -ne $os -and $null -ne $os.InstallDate) { ([datetime]$os.InstallDate).ToUniversalTime().ToString('o') } else { $null }
        Warnings          = @($warnings)
    }
}
