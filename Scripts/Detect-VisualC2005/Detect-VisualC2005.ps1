# Define registry paths
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)

$found = $false

foreach ($path in $registryPaths) {
    Get-ChildItem $path | ForEach-Object {
        $displayName = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DisplayName
        if ($displayName -like "*Visual C++ 2005*") {
            $uninstallString = (Get-ItemProperty $_.PSPath).UninstallString
            Write-Output "Found: $displayName"
            Write-Output "Uninstall String: $uninstallString"
            $found = $true
        }
    }
}

if (-not $found) {
    Write-Output "Visual C++ 2005 Redistributable not found."
}
