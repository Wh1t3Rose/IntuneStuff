# Zoom Detection Script
# Checks both Program Files and user AppData for Zoom installations

$zoomFound = $false

# Check Program Files (64-bit and 32-bit)
$programFilesPaths = @(
    "${env:ProgramFiles}\Zoom\bin\Zoom.exe",
    "${env:ProgramFiles(x86)}\Zoom\bin\Zoom.exe"
)

foreach ($path in $programFilesPaths) {
    if (Test-Path $path) {
        Write-Output "Zoom found at $path"
        $zoomFound = $true
    }
}

if ($zoomFound) {
    exit 0  # Detection success
} else {
    Write-Output "Zoom not found"
    exit 1  # Detection fail
}