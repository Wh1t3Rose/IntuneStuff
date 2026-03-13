<#
Copy-Modules-To-Prod.ps1
Copies module folders from the local Packaging\!Modules folder to
C:\Users\<User>\Highspring\Engineering Team - Modules\Prod

Usage (dry-run):
.\Copy-Modules-To-Prod.ps1 -WhatIf

Usage (actual):
.\Copy-Modules-To-Prod.ps1
#>
[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [string]$Source = (Join-Path $PSScriptRoot '!Modules'),
    [string]$Target = (Join-Path $env:USERPROFILE 'Highspring\Engineering Team - Modules\Prod')
)

if (-not (Test-Path -LiteralPath $Source)) { Write-Error "Source not found: $Source"; return }
if (-not (Test-Path -LiteralPath $Target)) { Write-Host "Creating target: $Target"; New-Item -ItemType Directory -Path $Target -Force | Out-Null }

$dirs = Get-ChildItem -LiteralPath $Source -Directory -ErrorAction Stop
foreach ($d in $dirs) {
    # Only copy folders that look like modules (contain .psm1 or .psd1)
    $hasModuleFile = (Get-ChildItem -LiteralPath $d.FullName -Filter '*.psm1' -File -Recurse -ErrorAction SilentlyContinue).Count -gt 0 -or (Get-ChildItem -LiteralPath $d.FullName -Filter '*.psd1' -File -Recurse -ErrorAction SilentlyContinue).Count -gt 0
    if (-not $hasModuleFile) { Write-Verbose "Skipping $($d.Name) - no module manifest/psm1 found"; continue }

    $dest = Join-Path $Target $d.Name
    if ($PSCmdlet.ShouldProcess("$d.FullName","Copy to $dest")) {
        Write-Host "Copying $($d.Name) -> $dest"
        Copy-Item -LiteralPath $d.FullName -Destination $dest -Recurse -Force
    }
}

Write-Host "Done. Verify in PowerShell (current session):"
Write-Host "Get-Module -ListAvailable | Where-Object { $_.ModuleBase -like '*Highspring*' }"
Write-Host "Or check automatic import: Get-Command -Name Add-UsersToIntuneGroup -ErrorAction SilentlyContinue"