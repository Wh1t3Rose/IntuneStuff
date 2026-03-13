# Remove ELAN TrackPoint / Touchpad Store apps using wildcards
$uwpPatterns = @(
    "*ELANTrackPoint*",
    "*TrackPoint*",
    "*Touchpad*"
)

foreach ($pattern in $uwpPatterns) {
    $apps = Get-AppxPackage -AllUsers | Where-Object { $_.Name -like $pattern }
    foreach ($app in $apps) {
        Write-Output "Removing UWP app $($app.Name)..."
        Remove-AppxPackage -Package $app.PackageFullName -AllUsers
    }
}
