# MobaXterm

## Description
PSAppDeployToolkit - This script performs the installation or uninstallation of an application(s).

## PSADT Version Required
4.1.6

## Install PSADT Module (Matching Version)
```powershell
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module -Name PSAppDeployToolkit -RequiredVersion 4.1.6 -Scope CurrentUser -Force
Import-Module -Name PSAppDeployToolkit -RequiredVersion 4.1.6 -Force
```

## Create PSADT Package Directory
```powershell
# Create a new package template folder using the installed PSADT module
$packageRoot = Join-Path (Get-Location) 'MobaXterm'
New-ADTTemplate -DestinationPath $packageRoot -ErrorAction Stop
```

## Package Content Preparation
1. Put required installer files (`.exe`, `.msi`, transforms, config files) in `Files` and/or `SupportFiles` under this package folder.
2. Update package variables and execution logic in Invoke-AppDeployToolkit.ps1 as needed for this app version.
3. Verify source filenames/arguments in the script match the files you placed in `Files`/`SupportFiles`.
4. Test install/uninstall command paths before packaging/uploading to Intune.

## Package Script
Invoke-AppDeployToolkit.ps1
