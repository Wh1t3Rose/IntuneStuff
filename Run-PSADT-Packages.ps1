<#
.SYNOPSIS
    Run the PSAppDeployToolkit `Invoke-AppDeployToolkit.exe` installer/uninstaller for each package under `!Ready`.

.DESCRIPTION
    Scans the provided `!Ready` folder for package folders containing a `Files` subfolder.
    For each package the script will look for `Invoke-AppDeployToolkit.exe` (searching the package root
    and subfolders), run it with `-DeploymentType Install|Uninstall -DeployMode Silent`, capture the exit code
    and console output, and then print a summary of successes and failures.

.PARAMETER ReadyFolder
    Root folder to search (defaults to `!Ready` in the script folder).

.PARAMETER Install
    If specified, install packages (default behavior).

.PARAMETER Uninstall
    If specified, uninstall packages instead of installing.

.PARAMETER DryRun
    If specified the script will only report what it would do without executing.

.PARAMETER LogFile
    Path to write a detailed log (defaults to `Run-PSADT-Packages.log` in the script folder).

.EXAMPLE
    .\Run-PSADT-Packages.ps1 -DryRun

.EXAMPLE
    .\Run-PSADT-Packages.ps1 -Install

.EXAMPLE
    .\Run-PSADT-Packages.ps1 -Uninstall
#>

param(
    [string]$ReadyFolder = $(Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath '!Ready'),
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$DryRun,
    [string]$LogFile = $(Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath 'Run-PSADT-Packages.log')
)

# Validate that only one of Install/Uninstall is specified
if ($Install -and $Uninstall) { Write-Error 'Cannot specify both -Install and -Uninstall'; exit 1 }
$deploymentType = if ($Uninstall) { 'Uninstall' } else { 'Install' }

function Write-Log { param($m,$lvl='INFO') $t=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); $l="[$t] [$lvl] $m"; Write-Output $l; Add-Content -Path $LogFile -Value $l }

"`n--- Run at $(Get-Date) ---`n" | Out-File -FilePath $LogFile -Encoding utf8 -Append

if (-not (Test-Path -Path $ReadyFolder)) { Write-Log "Ready folder not found: $ReadyFolder" 'ERROR'; throw "Ready folder not found: $ReadyFolder" }

# Find all 'Files' directories under Ready
$filesDirs = Get-ChildItem -Path $ReadyFolder -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq 'Files' }
if (-not $filesDirs -or $filesDirs.Count -eq 0) { Write-Log "No 'Files' directories found under $ReadyFolder" 'WARN'; Write-Host "No packages found under $ReadyFolder"; exit 0 }

$results = @()
foreach ($filesDir in $filesDirs) {
    $packageRoot = Split-Path -Parent $filesDir.FullName
    $packageName = Split-Path -Leaf $packageRoot
    Write-Host "Processing package: " -NoNewline; Write-Host "${packageName}" -ForegroundColor Cyan
    Write-Log "Processing package: $packageName (Files at: $($filesDir.FullName))" 'INFO'

    # Try to locate Invoke-AppDeployToolkit.exe anywhere in the package root
    $exe = Get-ChildItem -Path $packageRoot -Recurse -Filter Invoke-AppDeployToolkit.exe -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $exe) {
        Write-Log "Invoke-AppDeployToolkit.exe not found in package: $packageName" 'WARN'
        $results += [PSCustomObject]@{ Package = $packageName; PackagePath = $packageRoot; Executable = $null; ExitCode = $null; Success = $false; Note = 'Exe not found' }
        continue
    }

    $exePath = $exe.FullName
    Write-Host "Found PSADT exe for " -NoNewline; Write-Host "${packageName}" -ForegroundColor Cyan -NoNewline; Write-Host ": ${exePath}" -ForegroundColor Yellow
    Write-Log "Found PSADT exe for ${packageName}: ${exePath}" 'INFO'

    if ($DryRun) {
        Write-Host "Dry-run: would execute " -NoNewline; Write-Host "${packageName}" -ForegroundColor Cyan -NoNewline; Write-Host " (${deploymentType})"
        Write-Log "Dry-run: would run: $exePath -DeploymentType ${deploymentType} -DeployMode Silent" 'INFO'
        $results += [PSCustomObject]@{ Package = $packageName; PackagePath = $packageRoot; Executable = $exePath; ExitCode = $null; Success = $null; Note = 'DryRun' }
        continue
    }

    # Execute the deployment in its directory and capture output
    $workDir = Split-Path -Parent $exePath
    try {
        Push-Location -Path $workDir
        Write-Host "Starting ${deploymentType} for " -NoNewline; Write-Host "${packageName}" -ForegroundColor Cyan
        Write-Log "Starting ${deploymentType} for $packageName in $workDir" 'INFO'
        $outFile = Join-Path -Path $workDir -ChildPath "InstallOutput_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

        # Run and capture output
        $psiArgs = '-DeploymentType',$deploymentType,'-DeployMode','Silent'
        try {
            $processOutput = & $exePath @psiArgs 2>&1 | Tee-Object -FilePath $outFile
            $exit = $LASTEXITCODE
            Write-Host "Completed: " -NoNewline; Write-Host "${packageName}" -ForegroundColor Cyan -NoNewline; if ($exit -eq 0) { Write-Host " [SUCCESS]" -ForegroundColor Green } else { Write-Host " [FAILED: ExitCode=$exit]" -ForegroundColor Red }
            Write-Log "Completed: $packageName ExitCode=$exit (output saved to $outFile)" 'INFO'
            $success = ($exit -eq 0)
            $results += [PSCustomObject]@{ Package = $packageName; PackagePath = $packageRoot; Executable = $exePath; ExitCode = $exit; Success = $success; Note = $outFile }
        } catch {
            Write-Log "Execution failed for ${packageName}: $($_.Exception.Message)" 'ERROR'
            $results += [PSCustomObject]@{ Package = $packageName; PackagePath = $packageRoot; Executable = $exePath; ExitCode = $null; Success = $false; Note = $_.Exception.Message }
        }
    } finally {
        Pop-Location
    }
}

# Summary
$successes = $results | Where-Object { $_.Success -eq $true }
$failures = $results | Where-Object { $_.Success -ne $true }

Write-Host "`nRun complete. Packages processed: " -ForegroundColor Green -NoNewline; Write-Host "$($results.Count)" -ForegroundColor Cyan
Write-Host "Successful: " -ForegroundColor Green -NoNewline; Write-Host "$($successes.Count)" -ForegroundColor Green
foreach ($s in $successes) { Write-Host " - " -NoNewline; Write-Host "$($s.Package)" -ForegroundColor Cyan -NoNewline; Write-Host " (ExitCode: " -NoNewline; Write-Host "$($s.ExitCode)" -ForegroundColor Green -NoNewline; Write-Host ") - Output: $($s.Note)" }
Write-Host "Failed/Skipped: " -ForegroundColor Red -NoNewline; Write-Host "$($failures.Count)" -ForegroundColor Red
foreach ($f in $failures) { Write-Host " - " -NoNewline; Write-Host "$($f.Package)" -ForegroundColor Cyan -NoNewline; if ($f.ExitCode -and $f.ExitCode -ne 0) { Write-Host " (ExitCode: " -NoNewline; Write-Host "$($f.ExitCode)" -ForegroundColor Red -NoNewline; Write-Host ") : $($f.Note)" } else { Write-Host " : $($f.Note)" } }

Write-Log "Summary: Processed=$($results.Count) Success=$($successes.Count) Failed=$($failures.Count)" 'INFO'
Write-Log 'Detailed results:' 'INFO'
foreach ($r in $results) { Write-Log ("{0} | Exe: {1} | ExitCode: {2} | Note: {3}" -f $r.Package, ($r.Executable -or '<none>'), ($r.ExitCode -as [string]), ($r.Note -or '')) 'INFO' }

if ($failures.Count -gt 0) { exit 1 } else { exit 0 }
