<#
.SYNOPSIS
Brief description for Entra-Stale-Cleanup-List-Staggered.ps1

.DESCRIPTION
Add a longer description for Entra-Stale-Cleanup-List-Staggered.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\Entra-Stale-Cleanup-List-Staggered.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-09-15
Blog: blog.tylercox.tech
#>
# Connect to Graph
Connect-MgGraph -Scopes "Device.ReadWrite.All"

# Load device IDs
$deviceIds = Get-Content "C:\Temp\364-Entra_Unknown_OS_before90days.txt" | ForEach-Object { $_.Trim() }

# Delete in batches of 50
for ($i = 0; $i -lt $deviceIds.Count; $i += 50) {
    $endIndex = [Math]::Min($i + 49, $deviceIds.Count - 1)
    $batch = $deviceIds[$i..$endIndex]

    $deletedCount = 0
    foreach ($deviceId in $batch) {
        Remove-MgDevice -DeviceId $deviceId -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Deleting device: $deviceId"
        $deletedCount++
    }

    Write-Host "Deleted $deletedCount devices in this cycle."

    # Wait 30 minutes before next batch (unless it's the last batch)
    if ($i + 50 -lt $deviceIds.Count) {
        Write-Host "Waiting 10 minutes before next batch..."
        Start-Sleep -Seconds 600
    }
}


