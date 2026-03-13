<#
.SYNOPSIS
    Adds a list of UPNs (user principal names) to a specified Distribution List (DL) in Exchange Online.
.DESCRIPTION
    Prompts the user to select a text file containing UPNs (one per line), then prompts for the email address of the target DL.
    Adds each UPN as a member to the specified DL using Exchange Online PowerShell.
.NOTES
    Requires Exchange Online PowerShell module and appropriate permissions.
#>

# Prompt for UPN list file
$upnFile = Read-Host "Enter the path to the .txt file containing UPNs (one per line)"
if (-not (Test-Path $upnFile)) {
    Write-Host "File not found: $upnFile" -ForegroundColor Red
    exit 1
}

# Read UPNs from file
$upns = Get-Content $upnFile | Where-Object { $_ -and $_.Trim() -ne '' }
if ($upns.Count -eq 0) {
    Write-Host "No UPNs found in file." -ForegroundColor Yellow
    exit 1
}

# Prompt for DL email address
$dlEmail = Read-Host "Enter the email address of the Distribution List (DL) to add members to"
if (-not $dlEmail) {
    Write-Host "No DL email address provided." -ForegroundColor Red
    exit 1
}

# Connect to Exchange Online if not already connected
if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
    Install-Module ExchangeOnlineManagement -Force
}
if (-not (Get-Command Connect-ExchangeOnline -ErrorAction SilentlyContinue)) {
    Import-Module ExchangeOnlineManagement
}
if (-not (Get-PSSession | Where-Object { $_.ComputerName -like '*outlook.office365.com*' })) {
    Connect-ExchangeOnline -UserPrincipalName (Read-Host "Enter your admin UPN for Exchange Online login")
}

# Add each UPN to the DL

$added = @()
$failed = @()

foreach ($upn in $upns) {
    $trimmedUpn = $upn.Trim()
    try {
        Add-DistributionGroupMember -Identity $dlEmail -Member $trimmedUpn -ErrorAction Stop
        Write-Host "Added $trimmedUpn to $dlEmail" -ForegroundColor Green
        $added += $trimmedUpn
    } catch {
        Write-Host ("Failed to add {0}: {1}" -f $trimmedUpn, $_.Exception.Message) -ForegroundColor Yellow
        $failed += $trimmedUpn
    }
}

$addedCount = $added.Count
$failedCount = $failed.Count
Write-Host "\nSummary:" -ForegroundColor Cyan
Write-Host ("Added:   {0}" -f $addedCount) -ForegroundColor Green
Write-Host ("Failed:  {0}" -f $failedCount) -ForegroundColor Yellow
if ($failedCount -gt 0) {
    Write-Host "\nFailed UPNs:" -ForegroundColor Yellow
    $failed | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
}
Write-Host "\nOperation complete." -ForegroundColor Cyan
