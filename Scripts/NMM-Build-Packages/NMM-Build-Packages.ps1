# --- Set working directory to current location ---
$WorkingDir = Get-Location
Write-Host "Working directory: $WorkingDir"

# --- Find the first subfolder to use as source folder ---
$SourceFolderObj = Get-ChildItem -Path $WorkingDir -Directory | Select-Object -First 1
if (-not $SourceFolderObj) {
    Write-Error "No subfolder found in $WorkingDir to use as source folder!"
    exit 1
}
$SourceFolder = $SourceFolderObj.FullName
$PackageName = $SourceFolderObj.Name
Write-Host "Using source folder: $SourceFolder"

# --- Define other paths ---
$SfxModule = Join-Path $WorkingDir "7zSD.sfx"
$ConfigFile = Join-Path $WorkingDir "config.txt"
$ArchiveFile = Join-Path $WorkingDir "$PackageName.7z"

# --- Set output EXE folder ---
$OutputFolder = "C:\Users\TylerCox\OneDrive - Highspring\Packaging\!Packages\NinjaOne"
if (-not (Test-Path $OutputFolder)) { New-Item -Path $OutputFolder -ItemType Directory | Out-Null }
$OutputExe = Join-Path $OutputFolder "$PackageName.exe"
Write-Host "Output EXE will be: $OutputExe"

# --- Create config.txt ---
@"
;!@Install@!UTF-8!
Title="$PackageName Deployment"
RunProgram=".\Invoke-AppDeployToolkit.exe -DeploymentType Install -DeployMode NonInteractive"
GUIMode="0"
;!@InstallEnd@!
"@ | Set-Content -Path $ConfigFile -Encoding UTF8

if (Test-Path $ConfigFile) {
    Write-Host "Config.txt created at $ConfigFile"
} else {
    Write-Error "Failed to create config.txt!"
    exit 1
}

# --- Create the 7z archive ---
if (Test-Path $ArchiveFile) { Remove-Item $ArchiveFile -Force }
& "C:\Program Files\7-Zip\7z.exe" a -t7z $ArchiveFile "$SourceFolder\*" -mx9
Write-Host "Created archive: $ArchiveFile"

# --- Combine SFX + config + archive into EXE ---
cmd /c "copy /b `"$SfxModule`" + `"$ConfigFile`" + `"$ArchiveFile`" `"$OutputExe`" >nul"
Write-Host "Built SFX package: $OutputExe"
