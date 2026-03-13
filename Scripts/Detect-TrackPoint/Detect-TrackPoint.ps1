# Detect ELAN TrackPoint / Touchpad Store apps using wildcards
$uwpPatterns = @(
    "*ELANTrackPoint*",
    "*TrackPoint*",
    "*Touchpad*"
)

$found = $false
foreach ($pattern in $uwpPatterns) {
    $apps = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $pattern }
    if ($apps) {
        $found = $true
        break
    }
}

if ($found) {
    Write-Output "Installed"
    exit 1  # triggers remediation
} else {
    Write-Output "Not Installed"
    exit 0
}
