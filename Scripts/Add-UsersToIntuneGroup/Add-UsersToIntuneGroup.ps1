<#
.SYNOPSIS
Adds users (by UPN) from a CSV into an Azure AD (Intune) group using Microsoft Graph.

.DESCRIPTION
Prompts for the target group's display name and a path to a CSV file containing user UPNs.
Connects to Microsoft Graph (interactive) and adds each resolved user to the group.

CSV requirements:
- A header named `UPN`, `UserPrincipalName`, or `Email` is recognized.
- If no header is present, the script treats each line as a UPN.

REQUIREMENTS:
- PowerShell 7+ or Windows PowerShell with PowerShellGet
- Microsoft.Graph PowerShell SDK installed (script will offer to install)
- Graph app permissions (delegated) for `Group.ReadWrite.All` and `User.Read.All`

.EXAMPLE
.
PS> .\Add-UsersToIntuneGroup.ps1

#>

<#
CHANGELOG

- 2026-01-26  v0.3
    - Robust CSV parsing, path resolution, and header heuristics.
    - Microsoft.Graph import fallback to submodules when umbrella import exceeds
        function-capacity; improved import error handling.
    - Auto-relaunch into PowerShell 7 (pwsh) when available.
    - Fixed interpolation and parser errors; normalized Get-MgGroup results
        (handles .Value paging) and added diagnostics + manual group-id fallback.
    - Fixed unmatched-brace parsing issues.

- 2025-12-01  v0.2
    - Initial public version: reads CSV and adds UPNs to Intune group via Graph.
#>

[CmdletBinding()]
param()

function Ensure-Module {
    param(
        [string]$Name
    )
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Module $Name not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to install module $Name. $_"
            return $false
        }
    }
    return $true
}

Write-Host "Add users to an Intune/Azure AD group (via Microsoft Graph)" -ForegroundColor Cyan

# Prompt for group display name
$groupName = Read-Host -Prompt 'Enter the target Intune group display name'
if ([string]::IsNullOrWhiteSpace($groupName)) {
    Write-Error 'Group name cannot be empty. Exiting.'
    exit 1
}

# Prompt for CSV path
$csvPath = Read-Host -Prompt 'Enter path to CSV file (UPNs). Press Enter to browse'
if ([string]::IsNullOrWhiteSpace($csvPath)) {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $ofd = New-Object System.Windows.Forms.OpenFileDialog
        $ofd.Filter = 'CSV Files (*.csv)|*.csv|All files (*.*)|*.*'
        $ofd.Multiselect = $false
        if ($ofd.ShowDialog() -eq 'OK') { $csvPath = $ofd.FileName }
    } catch {
        $csvPath = Read-Host -Prompt 'Enter path to CSV file (no GUI available)'
    }
}

# Sanitize path: trim whitespace and surrounding quotes, then try to resolve to full path
$csvPath = $csvPath.Trim()
$csvPath = $csvPath.Trim('"')
$csvPath = $csvPath.Trim("'")
try {
    $resolved = Resolve-Path -Path $csvPath -ErrorAction SilentlyContinue
    if ($resolved) { $csvPath = $resolved.ProviderPath }
}
catch { }

if (-not (Test-Path -LiteralPath $csvPath)) {
    Write-Error "CSV file not found: '$csvPath' (checked literal path). Ensure the file exists and remove surrounding quotes from the path if present.)"
    exit 2
}

# If running Windows PowerShell, prefer relaunching under PowerShell 7 (pwsh)
# to avoid Microsoft.Graph function-capacity limits. Attempt auto-relaunch if pwsh is available.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $pwshCmd = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($pwshCmd) {
        Write-Host "Detected Windows PowerShell. Re-launching this script in PowerShell 7 (pwsh) for better Microsoft.Graph compatibility..." -ForegroundColor Yellow
        & $pwshCmd.Path -NoProfile -ExecutionPolicy Bypass -File $MyInvocation.MyCommand.Definition
        exit $LASTEXITCODE
    }
    else {
        Write-Warning "PowerShell 7 (pwsh) not found. If you continue to see 'function capacity' errors, install PowerShell 7+ or run this script in pwsh." 
    }
}

# Ensure Microsoft.Graph (prefer importing only required submodules to avoid function-capacity limits)
try {
    # Attempt a plain import of the umbrella module first
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Ensure-Module -Name Microsoft.Graph | Out-Null
    }
    Import-Module Microsoft.Graph -ErrorAction Stop
}
catch [System.Management.Automation.SessionStateOverflowException] {
    Write-Warning "Importing the full Microsoft.Graph module failed due to function capacity limits. Importing only required submodules."
    # Fall back to installing/importing only the needed submodules
    $needed = @('Microsoft.Graph.Users','Microsoft.Graph.Groups')
    foreach ($m in $needed) {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            Write-Host "Installing module $m..." -ForegroundColor Yellow
            $ok = Ensure-Module -Name $m
            if (-not $ok) { Write-Error "Failed to install $m"; exit 3 }
        }
        try {
            Import-Module $m -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to import ${m}: $($_.Exception.Message)"
            exit 3
        }
    }
}
catch {
    # Generic failure: try to import submodules directly
    Write-Warning "Importing Microsoft.Graph failed: $($_.Exception.Message). Attempting to import required submodules."
    $needed = @('Microsoft.Graph.Users','Microsoft.Graph.Groups')
    foreach ($m in $needed) {
        if (-not (Get-Module -ListAvailable -Name $m)) {
            Write-Host "Installing module $m..." -ForegroundColor Yellow
            $ok = Ensure-Module -Name $m
            if (-not $ok) { Write-Error "Failed to install $m"; exit 3 }
        }
        try {
            Import-Module $m -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to import ${m}: $($_.Exception.Message)"
            exit 3
        }
    }
}

# Connect to Microsoft Graph interactively
Write-Host 'Connecting to Microsoft Graph (interactive)...' -ForegroundColor Yellow
try {
    Connect-MgGraph -Scopes 'Group.ReadWrite.All','User.Read.All' -ErrorAction Stop
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 4
}

# Ensure required Microsoft.Graph submodules are loaded (some installs split the SDK into submodules)
try {
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Import-Module Microsoft.Graph.Groups -ErrorAction Stop
}
catch {
    Write-Error "Failed to import Microsoft.Graph submodules: $($_.Exception.Message)"
    Write-Host "Try running: Import-Module Microsoft.Graph.Users; Import-Module Microsoft.Graph.Groups" -ForegroundColor Yellow
    Write-Host "Or reinstall the SDK: Install-Module Microsoft.Graph -Scope CurrentUser -Force" -ForegroundColor Yellow
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    exit 4
}

# Resolve group by displayName
Write-Host "Searching for group: '$groupName'..." -ForegroundColor Yellow
try {
    $groups = Get-MgGroup -Filter "displayName eq '$($groupName.Replace("'","''"))'" -ConsistencyLevel eventual -CountVariable cnt -ErrorAction Stop
}
catch {
    Write-Error "Error while searching for group: $_"
    exit 5
}

# Normalize possible collection shapes returned by Get-MgGroup (some SDKs return a .Value page)
$groupList = @()
if ($null -ne $groups) {
    if ($groups.PSObject.Properties.Match('Value').Count -gt 0 -and $groups.Value) {
        $groupList = @($groups.Value)
    }
    else {
        try { $groupList = @($groups) } catch { $groupList = @() }
    }
}

if ($groupList.Count -eq 0) {
    Write-Warning "No group found with display name '$groupName'."
    $create = Read-Host -Prompt 'Create a new security group with this name? (Y/N)'
    if ($create -match '^[Yy]') {
        try {
            $newGroup = New-MgGroup -BodyParameter @{ displayName = $groupName; mailEnabled = $false; mailNickname = ($groupName -replace '\\s+','') ; securityEnabled = $true } -ErrorAction Stop
            $group = $newGroup
            Write-Host "Created group '$groupName' with id $($group.Id)" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create group: $_"
            exit 6
        }
    }
    else { Write-Error 'No group to add members to. Exiting.'; exit 7 }
}
elseif ($groupList.Count -gt 1) {
    Write-Warning "Multiple groups found with that display name. Using the first match. Consider using an exact group id in future."
    $group = $groupList[0]
}
else {
    $group = $groupList[0]
}

$groupId = if ($null -ne $group) { $group.Id } else { $null }
Write-Host "Target group id: $groupId" -ForegroundColor Cyan

# Validate resolved group id — fail fast with diagnostics if missing
if (-not $group -or [string]::IsNullOrWhiteSpace($groupId)) {
    Write-Error "Failed to resolve a valid group for '$groupName'."
    $countInfo = if ($null -ne $groups) { $groups.Count } else { 'null' }
    Write-Host "Diagnostic: Get-MgGroup returned count = $countInfo" -ForegroundColor Yellow
    if ($null -ne $groups -and $groups.Count -gt 0) {
        Write-Host "First returned group object (summary):" -ForegroundColor Yellow
        $groups[0] | Select-Object Id,displayName,mail,mailEnabled,securityEnabled | Format-List
    }

    $manual = Read-Host -Prompt 'Enter an existing group id to use (or press Enter to abort)'
    if ([string]::IsNullOrWhiteSpace($manual)) {
        Write-Error 'No valid group id available. Aborting.'
        exit 5
    }
    else {
        $groupId = $manual.Trim()
        Write-Host "Using manual group id: $groupId" -ForegroundColor Cyan
    }
}

# Read CSV (robust handling for headered or single-column files)
Write-Host "Reading CSV: $csvPath" -ForegroundColor Yellow
try {
    $rawLines = Get-Content -Path $csvPath -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    if (-not $rawLines -or $rawLines.Count -eq 0) {
        Write-Error 'CSV is empty.'
        exit 9
    }

    $firstLine = $rawLines[0]
    $headerIndicators = 'UPN|UserPrincipalName|UserPrincipalName|Email'
    $emailRegex = '^[^@\s]+@[^@\s]+\.[^@\s]+$'

    if ($firstLine -match '(?i)\b(UPN|UserPrincipalName|Email)\b') {
        # Standard CSV with header row
        $csv = Import-Csv -Path $csvPath -ErrorAction Stop
        if (-not $csv -or $csv.Count -eq 0) { Write-Error 'CSV is empty.'; exit 9 }

        # Try to find a named column first
        $possibleCols = @('UPN','UserPrincipalName','Email')
        $props = $csv | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
        $col = $props | Where-Object { $possibleCols -contains $_ } | Select-Object -First 1

        if (-not $col) {
            # Fallback: pick the column whose values look most like emails
            $best = $null; $bestCount = 0
            foreach ($p in $props) {
                $count = ($csv | Where-Object { $_.$p -match $emailRegex }).Count
                if ($count -gt $bestCount) { $bestCount = $count; $best = $p }
            }
            if ($best) { $col = $best }
        }

        if ($col) {
            $upns = $csv | ForEach-Object { ($_.$col).ToString().Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }
        else {
            Write-Error 'CSV did not contain a recognizable UPN column. Use header UPN or provide a single-column CSV of UPNs.'
            exit 8
        }
    }
    elseif ($firstLine -notmatch ',') {
        # Single-column file (one UPN per line)
        $upns = $rawLines | ForEach-Object { $_.Trim() } | Where-Object { $_ -match $emailRegex }
    }
    else {
        # Comma-delimited but headerless -- try Import-Csv and detect best column by value pattern
        $csv = Import-Csv -Path $csvPath -ErrorAction Stop
        $props = $csv | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
        $best = $null; $bestCount = 0
        foreach ($p in $props) {
            $count = ($csv | Where-Object { $_.$p -match $emailRegex }).Count
            if ($count -gt $bestCount) { $bestCount = $count; $best = $p }
        }
        if ($best) {
            $upns = $csv | ForEach-Object { ($_.$best).ToString().Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        }
        else {
            Write-Error 'Unable to determine UPN column in CSV.'
            exit 8
        }
    }
}
catch {
    Write-Error "Failed to read CSV: $_"
    exit 10
}

if (-not $upns -or $upns.Count -eq 0) { Write-Error 'No UPNs found in CSV.'; exit 11 }

Write-Host "Found $($upns.Count) UPNs to process." -ForegroundColor Cyan

$results = [System.Collections.Generic.List[PSObject]]::new()

foreach ($upn in $upns) {
    Write-Host "Processing: $upn" -NoNewline
    try {
        $user = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
        if (-not $user) {
            Write-Host " -> User not found" -ForegroundColor Yellow
            $results.Add([pscustomobject]@{ UPN = $upn; Status = 'NotFound'; Message = 'User not found' })
            continue
        }

        # Check membership
        $isMember = $false
        try {
            $members = Get-MgGroupMember -GroupId $groupId -All -ErrorAction Stop
            foreach ($m in $members) { if ($m.Id -eq $user.Id) { $isMember = $true; break } }
        }
        catch {
            Write-Host " -> Failed to enumerate members: $_" -ForegroundColor Yellow
        }

        if ($isMember) {
            Write-Host " -> Already member" -ForegroundColor Green
            $results.Add([pscustomobject]@{ UPN = $upn; Status = 'AlreadyMember'; Message = '' })
            continue
        }

        # Add member
        $body = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($user.Id)" }
        try {
            New-MgGroupMemberByRef -GroupId $groupId -BodyParameter $body -ErrorAction Stop
            Write-Host " -> Added" -ForegroundColor Green
            $results.Add([pscustomobject]@{ UPN = $upn; Status = 'Added'; Message = '' })
        }
        catch {
            Write-Host " -> Failed to add: $_" -ForegroundColor Red
            $results.Add([pscustomobject]@{ UPN = $upn; Status = 'Failed'; Message = $_.Exception.Message })
        }
    }
    catch {
        Write-Host " -> Error: $_" -ForegroundColor Red
        $results.Add([pscustomobject]@{ UPN = $upn; Status = 'Error'; Message = $_.Exception.Message })
    }
}

# Summary
Write-Host "\nSummary:" -ForegroundColor Cyan
$results | Group-Object -Property Status | ForEach-Object { Write-Host "$_ : $($_.Count)" }

# Optionally export results
$out = Read-Host -Prompt 'Enter path to save results CSV (or press Enter to skip)'
if (-not [string]::IsNullOrWhiteSpace($out)) {
    $results | Export-Csv -Path $out -NoTypeInformation -Force
    Write-Host "Results saved to $out" -ForegroundColor Green
}

Write-Host 'Done.' -ForegroundColor Cyan

# Disconnect
try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
