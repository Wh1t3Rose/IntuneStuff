# Intune Detection Script for Classic Microsoft Teams and Machine-Wide Installer

$classicTeamsFound = $false
$machineWideInstallerFound = $false

# --- Check for Classic Teams ---
$classicTeamsPaths = @(
    "$env:LOCALAPPDATA\Microsoft\Teams",
    "$env:ProgramFiles\Microsoft Teams",
    "$env:ProgramFiles(x86)\Microsoft Teams"
)

foreach ($path in $classicTeamsPaths) {
    if (Test-Path $path) {
        Write-Output "Classic Teams found at: $path"
        $classicTeamsFound = $true
        break
    }
}

# --- Check for Machine-Wide Installer ---
$installerRegistryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

foreach ($regPath in $installerRegistryPaths) {
    $keys = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
    foreach ($key in $keys) {
        $displayName = (Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue).DisplayName
        if ($displayName -like "*Teams Machine-Wide Installer*") {
            Write-Output "Teams Machine-Wide Installer found in registry: $displayName"
            $machineWideInstallerFound = $true
            break
        }
    }
    if ($machineWideInstallerFound) { break }
}

# --- Exit with 1 if any are found ---
if ($classicTeamsFound -or $machineWideInstallerFound) {
    Write-Output "Detection: Classic Teams or Machine-Wide Installer found. Remediation needed."
    exit 1
} else {
    Write-Output "Detection: Neither Classic Teams nor Machine-Wide Installer found."
    exit 0
}