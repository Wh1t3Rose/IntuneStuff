# Simulate Intune detection
$zoomFound = $false
$usersRoot = "$env:SystemDrive\Users"

Get-ChildItem -Path $usersRoot -Directory | ForEach-Object {
    $zoomPath = Join-Path $_.FullName "AppData\Roaming\Zoom\bin\Zoom.exe"
    if (Test-Path $zoomPath) {
        Write-Host "Found Zoom at $zoomPath"
        $zoomFound = $true
    }
}

if ($zoomFound) { 
    Write-Host "EXIT 0 - Requirement Met"
    exit 0 
} else { 
    Write-Host "EXIT 1 - Requirement Not Met"
    exit 1 
}
