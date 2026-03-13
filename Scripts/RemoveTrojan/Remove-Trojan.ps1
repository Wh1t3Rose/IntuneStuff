# Define variables
$UserDownloads = "C:\Users\DominiquePierce\Downloads"
$Pattern = "Chrome_Latest*.js"
$LogFolder = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = Join-Path $LogFolder "Delete_Chrome_Latest_Version_Log.txt"

# Ensure log folder exists
if (!(Test-Path $LogFolder)) {
    New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
}

# Log start
Add-Content -Path $LogFile -Value "`n[$(Get-Date)] - Starting cleanup script..."

# Find matching files
$Files = Get-ChildItem -Path $UserDownloads -Filter $Pattern -ErrorAction SilentlyContinue

if ($Files) {
    foreach ($File in $Files) {
        try {
            Remove-Item -Path $File.FullName -Force -ErrorAction Stop
            Add-Content -Path $LogFile -Value "[$(Get-Date)] - Deleted file: $($File.FullName)"
        }
        catch {
            Add-Content -Path $LogFile -Value "[$(Get-Date)] - ERROR deleting $($File.FullName): $($_.Exception.Message)"
        }
    }
} else {
    Add-Content -Path $LogFile -Value "[$(Get-Date)] - No matching files found."
}

# Log completion
Add-Content -Path $LogFile -Value "[$(Get-Date)] - Cleanup script completed."
