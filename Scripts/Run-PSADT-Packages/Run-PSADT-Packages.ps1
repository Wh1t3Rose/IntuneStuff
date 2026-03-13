<#
.SYNOPSIS
    Run the PSAppDeployToolkit `Invoke-AppDeployToolkit.exe` installer/uninstaller for each package under `!WorkingDir` or `!Ready`.

.DESCRIPTION
    Scans the selected source folder (`!WorkingDir` or `!Ready`) for package folders containing a `Files` subfolder.
    For each package the script will look for `Invoke-AppDeployToolkit.exe` (searching the package root
    and subfolders), run it with `-DeploymentType Install|Uninstall -DeployMode Silent`, capture the exit code
    and console output, and then print a summary of successes and failures.

.PARAMETER WorkingFolder
    Root folder to search. If not provided, the script asks whether to use `!WorkingDir` or `!Ready`.

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
    [string]$WorkingFolder = $(Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath '!WorkingDir'),
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

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition
$defaultWorkingFolder = Join-Path -Path $scriptRoot -ChildPath '!WorkingDir'
$readyFolder = Join-Path -Path $scriptRoot -ChildPath '!Ready'

if (-not $PSBoundParameters.ContainsKey('WorkingFolder')) {
    Write-Host "Select package source folder: [1] !WorkingDir  [2] !Ready" -ForegroundColor Cyan -NoNewline
    $folderChoice = Read-Host " (default: 1)"
    switch (($folderChoice | ForEach-Object { $_.Trim() })) {
        '2' {
            $WorkingFolder = $readyFolder
            Write-Log "Selected source folder: !Ready ($WorkingFolder)" 'INFO'
        }
        default {
            $WorkingFolder = $defaultWorkingFolder
            Write-Log "Selected source folder: !WorkingDir ($WorkingFolder)" 'INFO'
        }
    }
} else {
    Write-Log "Using WorkingFolder provided by parameter: $WorkingFolder" 'INFO'
}

if (-not (Test-Path -Path $WorkingFolder)) { Write-Log "Working folder not found: $WorkingFolder" 'ERROR'; throw "Working folder not found: $WorkingFolder" }

# Find all 'Files' directories under WorkingDir
$filesDirs = Get-ChildItem -Path $WorkingFolder -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq 'Files' }
if (-not $filesDirs -or $filesDirs.Count -eq 0) { Write-Log "No 'Files' directories found under $WorkingFolder" 'WARN'; Write-Host "No packages found under $WorkingFolder"; exit 0 }

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

# If all packages were successful, ask to copy to !Ready and optionally run upload script
if ($successes.Count -gt 0 -and $failures.Count -eq 0 -and -not $DryRun) {
    Write-Host "`nAll packages successful! " -ForegroundColor Green
    $copyResponse = Read-Host "Copy packages to !Ready folder? (Y/n)"
    if ([string]::IsNullOrEmpty($copyResponse) -or $copyResponse -ieq 'Y') {
        $ReadyFolder = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath '!Ready'
        
        # Copy package folders from !WorkingDir to !Ready
        if (Test-Path -Path $WorkingFolder) {
            if (-not (Test-Path -Path $ReadyFolder)) {
                New-Item -Path $ReadyFolder -ItemType Directory -Force | Out-Null
                Write-Log "Created !Ready folder: $ReadyFolder" 'INFO'
            }
            
            $copiedCount = 0
            foreach ($filesDir in $filesDirs) {
                $packageRoot = Split-Path -Parent $filesDir.FullName
                $packageName = Split-Path -Leaf $packageRoot
                $srcPath = $packageRoot
                $destPath = Join-Path -Path $ReadyFolder -ChildPath $packageName
                Copy-Item -Path $srcPath -Destination $destPath -Recurse -Force
                Write-Log "Copied package folder $packageName to !Ready" 'INFO'
                Write-Host "Copied " -NoNewline; Write-Host "$packageName" -ForegroundColor Cyan -NoNewline; Write-Host " to !Ready"
                $copiedCount++
            }
            
            if ($copiedCount -gt 0) {
                Write-Log "Copied $copiedCount package folder(s) to !Ready folder" 'INFO'
                
                # Ask if user wants to run Create-IntunePackages script
                $createResponse = Read-Host "Run .\Create-IntunePackages.ps1? (Y/n)"
                if ([string]::IsNullOrEmpty($createResponse) -or $createResponse -ieq 'Y') {
                    $createScript = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath 'Create-IntunePackages.ps1'
                    if (Test-Path -Path $createScript) {
                        Write-Log "Running Create-IntunePackages script: $createScript" 'INFO'
                        & $createScript
                    } else {
                        Write-Log "Create-IntunePackages script not found at: $createScript" 'ERROR'
                    }
                }
            }
        } else {
            Write-Log "Working folder not found: $WorkingFolder" 'WARN'
        }
    } else {
        Write-Log "User chose not to copy packages to !Ready" 'INFO'
    }
}

if ($failures.Count -gt 0) { exit 1 } else { exit 0 }
