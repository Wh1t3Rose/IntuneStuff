<#
.SYNOPSIS
Brief description for Detect-PowerPlanBalanced.ps1

.DESCRIPTION
Add a longer description for Detect-PowerPlanBalanced.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\Detect-PowerPlanBalanced.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-09-15
Blog: blog.tylercox.tech
#>

# Detection script for Intune
# Verifies if the active power plan is Balanced

try {
    # Get all power plans
    $schemes = powercfg /L

    # Find active GUID
    $activeLine = $schemes | Where-Object { $_ -match "\*" }
    if ($activeLine -match '{([0-9a-fA-F-]+)}') {
        $ActiveSchemeGuid = $Matches[1]
    }

    # Find Balanced GUID
    $balancedLine = $schemes | Where-Object { $_ -match "Balanced" }
    if ($balancedLine -match '{([0-9a-fA-F-]+)}') {
        $BalancedGuid = $Matches[1]
    }

    if ($ActiveSchemeGuid -and $BalancedGuid -and ($ActiveSchemeGuid -ieq $BalancedGuid)) {
        Write-Output "Compliant: Balanced power plan is active."
        exit 0
    }
    else {
        Write-Output "Non-Compliant: Balanced power plan is not active."
        exit 1
    }
}
catch {
    Write-Output "Error: $_"
    exit 1
}



