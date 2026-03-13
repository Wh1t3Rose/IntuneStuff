# Dell Display Manager display name pattern
$DDMPattern = "Dell Display Manager*"

# Check 64-bit and 32-bit uninstall registry keys
$uninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$found = $false

foreach ($key in $uninstallKeys) {
    $apps = Get-ItemProperty $key -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -like $DDMPattern
    }

    if ($apps) {
        $found = $true
        break
    }
}

if ($found) {
    Write-Output "Dell Display Manager is installed."
    exit 1   # Detection failed (app is present)
} else {
    Write-Output "Dell Display Manager not found."
    exit 0   # Detection passed (app not present)
}