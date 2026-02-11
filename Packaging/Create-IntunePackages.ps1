<#
.SYNOPSIS
  Recursively scans the `!Ready` folder for package folders with a `Files` subfolder
  and uses IntuneWinAppUtil.exe to create `.intunewin` packages into `!Packages`.

.DESCRIPTION
  For each `Files` directory found under the `!Ready` tree the script will locate
  the first `.exe` or `.msi` present (optionally a pattern can be provided), then
  call `IntuneWinAppUtil.exe -c <source> -s <setup> -o <output>` to create the
  Intune package. Logging and dry-run are supported.

.PARAMETER IntuneWinAppUtilPath
  Path to `IntuneWinAppUtil.exe`. Defaults to the executable in this Packaging folder.

.PARAMETER ReadyFolder
  Root folder to search (defaults to `!Ready` in the same folder as this script).

.PARAMETER PackagesFolder
  Destination folder for created `.intunewin` packages (defaults to `!Packages`).

.PARAMETER SetupPattern
  File pattern to consider as setup (default: '*.exe','*.msi').

.PARAMETER DryRun
  If specified, the script will only show what it would do without running the packer.

#.EXAMPLE
#  .\Create-IntunePackages.ps1 -DryRun
#>

param(
    [string]$IntuneWinAppUtilPath = $(Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath 'IntuneWinAppUtil.exe'),
    [string]$ReadyFolder = $(Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath '!Ready'),
    [string]$PackagesFolder = $(Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath '!Packages'),
    [string[]]$SetupPattern = @('*.exe','*.msi'),
    [switch]$DryRun,
    [switch]$VerboseLogging
)

function Write-Log {
    param($Message, [string]$Level = 'INFO')
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[$ts] [$Level] $Message"
    Write-Output $line
    Add-Content -Path $LogFile -Value $line
}

# Load package manifest/answers if available
# (Manifest loading removed — script is non-interactive by default)

# Prepare log
$LogFile = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath 'Create-IntunePackages.log'
"`n--- Run at $(Get-Date) ---`n" | Out-File -FilePath $LogFile -Encoding utf8 -Append

if (-not (Test-Path -Path $IntuneWinAppUtilPath)) {
    Write-Log "IntuneWinAppUtil.exe not found at '$IntuneWinAppUtilPath'" 'ERROR'
    throw "IntuneWinAppUtil.exe not found at '$IntuneWinAppUtilPath'"
}

if (-not (Test-Path -Path $ReadyFolder)) {
    Write-Log "Ready folder not found: '$ReadyFolder'" 'ERROR'
    throw "Ready folder not found: '$ReadyFolder'"
}

if (-not (Test-Path -Path $PackagesFolder)) {
    Write-Log "Packages folder does not exist, creating: '$PackagesFolder'" 'INFO'
    if (-not $DryRun) { New-Item -Path $PackagesFolder -ItemType Directory -Force | Out-Null }
}

# Prepare upload folder inside Packages for processed files
$logCleanupCount = 0
$packageDirs = Get-ChildItem -Path $ReadyFolder -Directory -ErrorAction SilentlyContinue
foreach ($pkg in $packageDirs) {
  $logFiles = Get-ChildItem -Path $pkg.FullName -Filter 'InstallOutput*.log' -File -ErrorAction SilentlyContinue
  foreach ($log in $logFiles) {
    try {
      Remove-Item -Path $log.FullName -Force -ErrorAction Stop
      Write-Log "Deleted log file: $($log.FullName)" 'INFO'
      $logCleanupCount++
    } catch {
      Write-Log "Failed to delete log file: $($log.FullName) - $($_.Exception.Message)" 'WARN'
    }
  }
}
if ($logCleanupCount -gt 0) { Write-Log "Deleted $logCleanupCount InstallOutput*.log files from !Ready packages." 'INFO' }
$UploadFolder = Join-Path -Path $PackagesFolder -ChildPath '!upload'
if (-not (Test-Path -Path $UploadFolder)) {
  Write-Log "Upload folder does not exist, creating: '$UploadFolder'" 'INFO'
  if (-not $DryRun) { New-Item -Path $UploadFolder -ItemType Directory -Force | Out-Null }
}

Write-Log "Using Intune packaging tool: $IntuneWinAppUtilPath"
Write-Log "Scanning Ready folder: $ReadyFolder"
Write-Log "Output Packages folder: $PackagesFolder"

# Find all 'Files' directories under Ready
$filesDirs = Get-ChildItem -Path $ReadyFolder -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -ieq 'Files' }

if (-not $filesDirs -or $filesDirs.Count -eq 0) {
    Write-Log "No 'Files' directories found under $ReadyFolder" 'WARN'
    exit 0
}

foreach ($filesDir in $filesDirs) {
    $packageRoot = Split-Path -Parent $filesDir.FullName
    $packageName = Split-Path -Leaf $packageRoot

    Write-Log "Found package candidate: $packageName (Files at: $($filesDir.FullName))"

    # (Non-interactive manifest loading removed; script runs non-interactively by default)


    # Use Invoke-AppDeployToolkit.exe in the app root as the setup file, and app root as source
    $appRoot = Split-Path -Parent $filesDir.FullName
    $invokeAppToolkitExePath = Join-Path -Path $appRoot -ChildPath 'Invoke-AppDeployToolkit.exe'
    if (-not (Test-Path -Path $invokeAppToolkitExePath)) {
      Write-Log "Invoke-AppDeployToolkit.exe not found in $appRoot; skipping" 'WARN'
      continue
    }
    $sourceFolder = $appRoot
    $setupPath = $invokeAppToolkitExePath


    # Ensure unique output filename per app (use app root folder name and setup file name)
    $baseName = $packageName
    $outputName = "$baseName.intunewin"
    $outputPath = Join-Path -Path $UploadFolder -ChildPath $outputName
    $counter = 1
    while (Test-Path -Path $outputPath) {
      $outputName = "${baseName}_$counter.intunewin"
      $outputPath = Join-Path -Path $UploadFolder -ChildPath $outputName
      $counter++
    }
    # Add the -o argument to use the unique output path
    # Add per-app log entry for output file
    Write-Log "Output file for $($packageName): $($outputPath)"


    Write-Log "Packaging: $packageName -> $outputPath using setup Invoke-AppDeployToolkit.exe"

    if ($DryRun) { Write-Log "Dry-run: would run IntuneWinAppUtil.exe -c '$sourceFolder' -s '$setupPath' -o '$UploadFolder'"; continue }

    # Proceeding with packaging (no interactive prompts)

    try {
      $args = @('-c', $sourceFolder, '-s', $setupPath, '-o', $UploadFolder, '-q')
      Write-Log "Running: $IntuneWinAppUtilPath $($args -join ' ')"
      $procOutput = & $IntuneWinAppUtilPath @args 2>&1
      $exit = $LASTEXITCODE
      if ($procOutput) { $procOutput | ForEach-Object { Write-Log "OUT: $_" } }

      # Move the generated .intunewin file to the desired output path in !upload
      $generatedFile = Join-Path -Path $UploadFolder -ChildPath (Split-Path -Leaf $setupPath -Resolve).Replace('.exe','.intunewin')
      if (Test-Path -Path $generatedFile) {
        Move-Item -Path $generatedFile -Destination $outputPath -Force
        Write-Log "Moved generated file to: $outputPath"
      }

      if ($exit -eq 0) {
        Write-Log "Successfully created package: $outputPath"
      } else {
        Write-Log "IntuneWinAppUtil.exe exited with code $exit" 'ERROR'
      }
    }
    catch {
      Write-Log "Exception while running packer: $($_.Exception.Message)" 'ERROR'
    }
}

Write-Log "Processing complete."
