# Configure these for your organization
$org     = 'HighspringEnterpriseEngineering'
$project = 'HighspringProject'                 # <<< set your Azure DevOps project name
$feed    = 'HighspringEnterpriseEngineering'
$repoName = 'Highspring'

$feedV3 = "https://pkgs.dev.azure.com/$org/$project/_packaging/$feed/nuget/v3/index.json"
$feedV2 = "https://pkgs.dev.azure.com/$org/$project/_packaging/$feed/nuget/v2"

# Prompt for PAT (do NOT store in repo)
$pat = Read-Host -Prompt 'Enter feed PAT'
$securePat = ConvertTo-SecureString $pat -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('PAT',$securePat)

# Choose SourceLocation; validate $feedV3 first and fall back to v2 if needed.
$sourceLocation = if ([System.Uri]::IsWellFormedUriString($feedV3, [System.UriKind]::Absolute)) { $feedV3 } else { Write-Warning "feedV3 not well-formed; using feedV2"; $feedV2 }

# Ensure clean registration (Unregister if present, then register)
$existing = Get-PSRepository -Name $repoName -ErrorAction SilentlyContinue
if ($existing) {
    try { Unregister-PSRepository -Name $repoName -ErrorAction Stop; Write-Host "Unregistered existing PSRepository '$repoName'." } catch { Write-Warning "Could not unregister: $_. Continuing..." }
}

try {
    Register-PSRepository -Name $repoName -SourceLocation $sourceLocation -PublishLocation $feedV2 -InstallationPolicy Trusted -Credential $cred
    Write-Host "Registered PSRepository '$repoName' -> Source: $sourceLocation  Publish: $feedV2"
} catch {
    Write-Warning "Register-PSRepository failed: $_"
}

# -------------------------------------------------------------------------
# Diagnostics helper: shows files, sizes, attributes and a sample of contents
# -------------------------------------------------------------------------
function Inspect-ModuleFolder {
    param([string]$Folder)

    if (-not (Test-Path $Folder)) { Write-Warning "Folder not found: $Folder"; return }

    Write-Host "`n--- Directory listing (including hidden/system) ---"
    Get-ChildItem -Path $Folder -Recurse -Force | Select-Object FullName,Length,Attributes | Format-Table -AutoSize

    Write-Host "`n--- Look for manifest/psm1 files ---"
    Get-ChildItem -Path $Folder -Recurse -Force -Include '*.psd1','*.psm1' | Select-Object FullName,Length,Attributes | Format-Table -AutoSize

    Write-Host "`n--- Example file preview (first non-empty file) ---"
    $example = Get-ChildItem -Path $Folder -Recurse -Force -File | Where-Object { $_.Length -gt 0 } | Select-Object -First 1
    if ($example) {
        Write-Host "Previewing: $($example.FullName)"
        Get-Content -Path $example.FullName -TotalCount 40
    } else {
        Write-Warning "No non-empty files found under $Folder. This suggests OneDrive placeholders or zero-length files."
    }
}

# Example copy + import logic: prefer copying from repo working tree rather than OneDrive if possible.
# Update $repoModuleSrc to the repo path for the module (relative to this script).
$repoModuleSrc = Join-Path $PSScriptRoot '!Modules\Add-UsersToIntuneGroup'   # adjust if needed
$destRoot = Join-Path $env:USERPROFILE 'Documents\PowerShell\Modules'
$dest = Join-Path $destRoot 'Add-UsersToIntuneGroup'

if (Test-Path $repoModuleSrc) {
    # copy from repository source (avoids OneDrive placeholder problems)
    if (-not (Test-Path $destRoot)) { New-Item -ItemType Directory -Path $destRoot -Force | Out-Null }
    Copy-Item -Path $repoModuleSrc -Destination $dest -Recurse -Force
    Write-Host "Copied module from repo path to $dest"

    # Inspect the copied folder
    Inspect-ModuleFolder -Folder $dest

    # Try to import the manifest or psm1 explicitly if present
    $manifest = Get-ChildItem -Path $dest -Recurse -Force -Filter '*.psd1' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($manifest) {
        Import-Module -Name $manifest.FullName -Force -ErrorAction Stop
        Write-Host "Imported manifest: $($manifest.Name)"
    } else {
        $psm1 = Get-ChildItem -Path $dest -Recurse -Force -Filter '*.psm1' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($psm1) {
            Import-Module -Name $psm1.FullName -Force -ErrorAction Stop
            Write-Host "Imported psm1: $($psm1.Name)"
        } else {
            Write-Warning "No .psd1 or .psm1 under $dest. Check the scaffolded module contents."
        }
    }
} else {
    Write-Warning "Repo source module path not found: $repoModuleSrc. If you must copy from OneDrive, set \$srcOneDrive to that path and run Inspect-ModuleFolder on it first."
}