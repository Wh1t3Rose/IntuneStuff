<#
.SYNOPSIS
Checks whether the system meets minimum Windows build and recent Monthly (B) Cumulative Update requirements.

.DESCRIPTION
Determines the local OS build and validates it against minimum required builds for Windows 10 and Windows 11.
Then inspects the update history to find the most recent Monthly (B) Cumulative (security) update (KB5xxxxxx series)
and calculates how many days have passed since it was installed. Flags non-compliance when the OS build is below
the minimum or the last Monthly Cumulative update is older than 40 days.

.PARAMETER MinWin10Build
Minimum required build for Windows 10 (set in script).

.PARAMETER MinWin11Build
Minimum required build for Windows 11 (set in script).

.EXAMPLE
.\Detect-FailedWinUpgrades.ps1
Runs the compliance checks and exits with code 0 when compliant, 1 when non-compliant.

.INPUTS
None.

.OUTPUTS
Writes a short status string and exits with code:
0 - compliant (OS and Monthly CU checks passed)
1 - non-compliant (one or more checks failed)

.NOTES
Author: Tyler Cox
Created: 2025-10-14
Blog: blog.tylercox.tech
#>
# ...existing code...
# --- Minimum required builds ---
$MinWin10Build = 19045  # Windows 10 22H2
$MinWin11Build = 26100  # Windows 11 24H2

# --- Get OS version ---
$OSversion = [Version](Get-ComputerInfo -Property OsVersion).OsVersion
Write-Output "Detected OS version: $OSversion"

# --- Initialize compliance flags ---
$OSCompliant = $false
$CUCompliant = $false
$Reasons = @()

# --- Check OS compliance ---
if ($OSversion.Build -lt 22000) {   # Windows 10
    if ($OSversion.Build -ge $MinWin10Build) {
        $OSCompliant = $true
    } else {
        $Reasons += "OS version below minimum required ($OSversion)"
    }
} else {  # Windows 11
    if ($OSversion.Build -ge $MinWin11Build) {
        $OSCompliant = $true
    } else {
        $Reasons += "OS version below minimum required ($OSversion)"
    }
}

# --- Determine last Monthly (B) CU ---
$daysCU = $null
$timeout = [DateTime]::Now.AddMinutes(5)

do {
    try {
        $lastupdate = Get-HotFix |
                      Where-Object {
                          $_.HotFixID -match '^KB5\d{6,}$' -and
                          $_.Description -match 'Security Update'
                      } |
                      Sort-Object -Property InstalledOn |
                      Select-Object -Last 1 -ExpandProperty InstalledOn

        if ($lastupdate) {
            $daysCU = (New-TimeSpan -Start $lastupdate -End (Get-Date)).Days
        }
    }
    catch {
        $Reasons += "Error querying update history"
    }

    if ([DateTime]::Now -gt $timeout) { break }
} until ($null -ne $daysCU)

# --- Check Monthly CU compliance ---
if ($daysCU -eq $null) {
    $Reasons += "Could not determine last Monthly Cumulative (B) Update"
} elseif ($daysCU -le 40) {
    $CUCompliant = $true
} else {
    $Reasons += "Last Monthly Cumulative (B) Update was $daysCU days ago"
}

# --- Final Compliance Result ---
if ($OSCompliant -and $CUCompliant) {
    Write-Output "System is compliant. Reason: All checks passed."
    exit 0
} else {
    $CombinedReason = $Reasons -join "; "
    Write-Output "System is non-compliant. Reason(s): $CombinedReason"
    exit 1
}# --- Minimum required builds ---
$MinWin10Build = 19045  # Windows 10 22H2
$MinWin11Build = 26100  # Windows 11 24H2

# --- Get OS version ---
$OSversion = [Version](Get-ComputerInfo -Property OsVersion).OsVersion
Write-Output "Detected OS version: $OSversion"

# --- Initialize compliance flags ---
$OSCompliant = $false
$CUCompliant = $false
$Reasons = @()

# --- Check OS compliance ---
if ($OSversion.Build -lt 22000) {   # Windows 10
    if ($OSversion.Build -ge $MinWin10Build) {
        $OSCompliant = $true
    } else {
        $Reasons += "OS version below minimum required ($OSversion)"
    }
} else {  # Windows 11
    if ($OSversion.Build -ge $MinWin11Build) {
        $OSCompliant = $true
    } else {
        $Reasons += "OS version below minimum required ($OSversion)"
    }
}

# --- Determine last Monthly (B) CU ---
$daysCU = $null
$timeout = [DateTime]::Now.AddMinutes(5)

do {
    try {
        $lastupdate = Get-HotFix |
                      Where-Object {
                          $_.HotFixID -match '^KB5\d{6,}$' -and
                          $_.Description -match 'Security Update'
                      } |
                      Sort-Object -Property InstalledOn |
                      Select-Object -Last 1 -ExpandProperty InstalledOn

        if ($lastupdate) {
            $daysCU = (New-TimeSpan -Start $lastupdate -End (Get-Date)).Days
        }
    }
    catch {
        $Reasons += "Error querying update history"
    }

    if ([DateTime]::Now -gt $timeout) { break }
} until ($null -ne $daysCU)

# --- Check Monthly CU compliance ---
if ($daysCU -eq $null) {
    $Reasons += "Could not determine last Monthly Cumulative (B) Update"
} elseif ($daysCU -le 40) {
    $CUCompliant = $true
} else {
    $Reasons += "Last Monthly Cumulative (B) Update was $daysCU days ago"
}

# --- Final Compliance Result ---
if ($OSCompliant -and $CUCompliant) {
    Write-Output "System is compliant. Reason: All checks passed."
    exit 0
} else {
    $CombinedReason = $Reasons -join "; "
    Write-Output "System is non-compliant. Reason(s): $CombinedReason"
    exit 1
}

