<#
Fix-Modules-Manifests.ps1
Scans Dev and Prod module roots and repairs malformed .psd1 manifests.
Usage:
  pwsh -NoProfile -File .\Fix-Modules-Manifests.ps1 -DevRoot "$HOME\Highspring\Engineering Team - Modules\Dev" -ProdRoot "$HOME\Highspring\Engineering Team - Modules\Prod" -WhatIf
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$DevRoot = (Join-Path $env:USERPROFILE 'Highspring\Engineering Team - Modules\Dev'),
    [string]$ProdRoot = (Join-Path $env:USERPROFILE 'Highspring\Engineering Team - Modules\Prod')
)

function Write-Log { param($m) Write-Host $m -ForegroundColor Cyan }

function Fix-ManifestForModule {
    param(
        [string]$ModuleFolder
    )
    $moduleName = Split-Path -Path $ModuleFolder -Leaf
    $psd1 = Get-ChildItem -LiteralPath $ModuleFolder -Filter '*.psd1' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $psd1) {
        Write-Log "No .psd1 found for module $moduleName - will create one if possible."
    }

    $manifestPath = if ($psd1) { $psd1.FullName } else { Join-Path $ModuleFolder "$moduleName.psd1" }

    # Try to parse existing manifest. Some files may have been written incorrectly
    # (for example printed tables or unexpanded placeholders). Use raw content heuristics
    $isMalformed = $false
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $raw = Get-Content -Raw -LiteralPath $manifestPath -ErrorAction Stop
            # If file doesn't start with a PowerShell data file hashtable or contains literal placeholder, mark malformed
            if ($raw -notmatch '^[\s\r\n]*@\{' -or $raw -match '\$moduleName' -or $raw -match 'Name\s+Value') {
                Write-Log "Malformed manifest detected (heuristic): $manifestPath"
                $isMalformed = $true
            } else {
                try { Import-PowerShellDataFile -LiteralPath $manifestPath | Out-Null } catch { Write-Log "Malformed manifest detected parsing: $manifestPath : $($_.Exception.Message)"; $isMalformed = $true }
            }
        } catch {
            Write-Log "Failed reading manifest: $manifestPath : $($_.Exception.Message)"
            $isMalformed = $true
        }
    }

    # Determine root module (prefer .psm1 named same as module)
    $psm1 = Get-ChildItem -LiteralPath $ModuleFolder -Filter "$moduleName.psm1" -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $psm1) { $psm1 = Get-ChildItem -LiteralPath $ModuleFolder -Filter '*.psm1' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if (-not $psm1) {
        # Try to find a .ps1 script to be used as root (less ideal)
        $ps1 = Get-ChildItem -LiteralPath $ModuleFolder -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    }

    if (-not (Test-Path -LiteralPath $manifestPath) -or $isMalformed) {
        $rootName = if ($psm1) { $psm1.Name } elseif ($ps1) { $ps1.Name } else { "$moduleName.psm1" }
        $guid = [guid]::NewGuid().Guid
        $manifest = @"
@{
    RootModule = '$rootName'
    ModuleVersion = '0.1.0'
    GUID = '$guid'
    Author = 'YourOrg'
    CompanyName = 'YourOrg'
    Copyright = '(c) YourOrg'
    Description = 'Auto-fixed manifest for $moduleName'
    FunctionsToExport = @('$moduleName')
}
"@
        if ($PSBoundParameters.ContainsKey('WhatIf')) {
            Write-Log "Would back up and write manifest: $manifestPath (RootModule=$rootName)"
            return @{Module=$moduleName; Action='WouldFix'; Path=$manifestPath}
        }

        # Backup existing manifest if present
        if (Test-Path -LiteralPath $manifestPath) { Copy-Item -LiteralPath $manifestPath -Destination ($manifestPath + '.bak_') -Force }
        Set-Content -LiteralPath $manifestPath -Value $manifest -Encoding UTF8 -Force
        Write-Log "Wrote manifest: $manifestPath"

        # Try to import module manifest to verify
        try {
            Import-Module -Name $manifestPath -Force -ErrorAction Stop | Out-Null
            Write-Log "Imported module $moduleName successfully after fix."
            return @{Module=$moduleName; Action='Fixed'; Path=$manifestPath; Imported=$true}
        } catch {
            Write-Warning "Failed to import $moduleName after fix: $($_.Exception.Message)"
            return @{Module=$moduleName; Action='Fixed'; Path=$manifestPath; Imported=$false; Error=$_.Exception.Message}
        }
    } else {
        Write-Log "Manifest OK: $manifestPath"
        return @{Module=$moduleName; Action='OK'; Path=$manifestPath}
    }
}

function Process-Root {
    param([string]$RootPath)
    if (-not (Test-Path -LiteralPath $RootPath)) { Write-Log "Root not found: $RootPath"; return }
    $modules = Get-ChildItem -LiteralPath $RootPath -Directory -ErrorAction SilentlyContinue
    foreach ($m in $modules) {
        Fix-ManifestForModule -ModuleFolder $m.FullName
    }
}

Write-Log "Processing Dev: $DevRoot"
Process-Root -RootPath $DevRoot
Write-Log "Processing Prod: $ProdRoot"
Process-Root -RootPath $ProdRoot

Write-Log 'Done.'