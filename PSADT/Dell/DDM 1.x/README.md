# Dell Display Manager

## Description
This script performs the installation or uninstallation of Dell Display Manager.

## PSADT Version Required
Unknown

## Install PSADT Module (Matching Version)
```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
# NOTE: Version could not be auto-detected from this package script.
# Replace <REQUIRED_VERSION> with the correct PSADT version for this package.
Install-Module -Name PSAppDeployToolkit -RequiredVersion <REQUIRED_VERSION> -Scope CurrentUser -Force
Import-Module -Name PSAppDeployToolkit -RequiredVersion <REQUIRED_VERSION> -Force
```

## Create PSADT Package Directory
```powershell
# Create a new package template folder using the installed PSADT module
$packageRoot = Join-Path (Get-Location) 'Dell Display Manager'
New-ADTTemplate -DestinationPath $packageRoot -ErrorAction Stop
```

## Package Content Preparation
1. Put required installer files (`.exe`, `.msi`, transforms, config files) in `Files` and/or `SupportFiles` under this package folder.
2. Update package variables and execution logic in Deploy-Application.ps1 as needed for this app version.
3. Verify source filenames/arguments in the script match the files you placed in `Files`/`SupportFiles`.
4. Test install/uninstall command paths before packaging/uploading to Intune.

## Package Script
Deploy-Application.ps1
