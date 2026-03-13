<#

.SYNOPSIS
PSAppDeployToolkit - This script performs the installation or uninstallation of 7-Zip.

.DESCRIPTION
- The script is provided as a template to perform an install, uninstall, or repair of an application(s).
- The script either performs an "Install", "Uninstall", or "Repair" deployment type.
- The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.

The script imports the PSAppDeployToolkit module which contains the logic and functions required to install or uninstall an application.

PSAppDeployToolkit is licensed under the GNU LGPLv3 License - (C) 2025 PSAppDeployToolkit Team (Sean Lillis, Dan Cunningham, Muhammad Mashwani, Mitch Richters, Dan Gough).

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the
Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details. You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

.PARAMETER DeploymentType
The type of deployment to perform.

.PARAMETER DeployMode
Specifies whether the installation should be run in Interactive (shows dialogs), Silent (no dialogs), or NonInteractive (dialogs without prompts) mode.

NonInteractive mode is automatically set if it is detected that the process is not user interactive.

.PARAMETER AllowRebootPassThru
Allows the 3010 return code (requires restart) to be passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.

.PARAMETER TerminalServerMode
Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Desktop Session Hosts/Citrix servers.

.PARAMETER DisableLogging
Disables logging to file for the script.

.EXAMPLE
powershell.exe -File Invoke-AppDeployToolkit.ps1 -DeployMode Silent

.EXAMPLE
powershell.exe -File Invoke-AppDeployToolkit.ps1 -AllowRebootPassThru

.EXAMPLE
powershell.exe -File Invoke-AppDeployToolkit.ps1 -DeploymentType Uninstall

.EXAMPLE
Invoke-AppDeployToolkit.exe -DeploymentType "Install" -DeployMode "Silent"

.INPUTS
None. You cannot pipe objects to this script.

.OUTPUTS
None. This script does not generate any output.

.NOTES
Toolkit Exit Code Ranges:
- 60000 - 68999: Reserved for built-in exit codes in Invoke-AppDeployToolkit.ps1, and Invoke-AppDeployToolkit.exe
- 69000 - 69999: Recommended for user customized exit codes in Invoke-AppDeployToolkit.ps1
- 70000 - 79999: Recommended for user customized exit codes in PSAppDeployToolkit.Extensions module.

.LINK
https://psappdeploytoolkit.com

#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Install', 'Uninstall', 'Repair')]
    [PSDefaultValue(Help = 'Install', Value = 'Install')]
    [System.String]$DeploymentType,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Interactive', 'Silent', 'NonInteractive')]
    [PSDefaultValue(Help = 'Interactive', Value = 'Interactive')]
    [System.String]$DeployMode,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$AllowRebootPassThru,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$TerminalServerMode,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$DisableLogging
)


##================================================
## MARK: Variables
##================================================

$adtSession = @{
    # App variables.
    AppVendor = 'Igor Pavlov'
    AppName = '7-Zip'
    AppVersion = '25.01'
    AppArch = ''
    AppLang = 'EN'
    AppRevision = '01'
    AppSuccessExitCodes = @(0)
    AppRebootExitCodes = @(1641, 3010)
    AppScriptVersion = '1.0.0'
    AppScriptDate = '2025-08-07'
    AppScriptAuthor = 'Tyler Cox'

    # Install Titles (Only set here to override defaults set by the toolkit).
    InstallName = ''
    InstallTitle = ''

    # Script variables.
    DeployAppScriptFriendlyName = $MyInvocation.MyCommand.Name
    DeployAppScriptVersion = '4.0.6'
    DeployAppScriptParameters = $PSBoundParameters
}

function Install-ADTDeployment
{
    ##================================================
    ## MARK: Pre-Install
    ##================================================
    $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

    ## Microsoft Intune Win32 App Workaround - Check If Running 32-bit PowerShell on 64-bit OS, Restart as 64-bit Process

    if (!([Environment]::Is64BitProcess)) {
        if([Environment]::Is64BitOperatingSystem) {
            
            Write-ADTLogEntry -Message "Running 32-bit PowerShell on 64-bit OS, Restarting as 64-bit Process..." -Severity 1
            
            $arguments = "-NoProfile -ExecutionPolicy ByPass -WindowStyle Hidden -File `"" + $myinvocation.mycommand.definition + "`""
            $path = (Join-Path $Env:SystemRoot -ChildPath "\sysnative\WindowsPowerShell\v1.0\powershell.exe")

            Start-Process $path -ArgumentList $arguments -Wait
            
            Write-ADTLogEntry -Message "Finished Running x64 version of PowerShell" -Severity 1
            Exit
        }
        else {
            Write-ADTLogEntry -Message "Running 32-bit PowerShell on 32-bit OS" -Severity 1
        }
    }

    ## Show Welcome Message, close 7-Zip with a 60 second countdown before automatically closing.
    Show-ADTInstallationWelcome -CloseProcesses 7z,7zFM -CloseProcessesCountdown 60

    ## Show Progress Message (with a message to indicate the application is being uninstalled).
    Show-ADTInstallationProgress -StatusMessage 'Removing Any Existing Versions of 7-Zip. Please Wait...'

    Remove-Item -Path "C:\ProgramData\VACO\InstalledApps\7-zip_2501.tag" -ItemType File -Force

    ## Remove Any Existing Versions of 7-Zip (MSI)
    Uninstall-ADTApplication -Name '7-Zip' -ApplicationType 'MSI' -ErrorAction SilentlyContinue

    ## Remove Any Existing Versions of 7-Zip (EXE)
    Uninstall-ADTApplication -Name '7-Zip' -ApplicationType 'EXE' -ArgumentList '/S' -ErrorAction SilentlyContinue

    Start-ADTProcess -FilePath "C:\Program Files\7-Zip\Uninstall.exe" -ArgumentList '/S' -ErrorAction SilentlyContinue

    Start-ADTProcess -FilePath "Files\7z2501-x64.msi" -ArgumentList '/x' -ErrorAction SilentlyContinue

    ##================================================
    ## MARK: Install
    ##================================================
    $adtSession.InstallPhase = $adtSession.DeploymentType

    ## Perform 7-Zip Installation

    if ($ENV:PROCESSOR_ARCHITECTURE -eq 'x86'){
        Write-ADTLogEntry -Message "Detected 32-bit OS Architecture" -Severity 1

        ## Install 7-Zip on 32-bit OS

        $files = Get-ChildItem -Path "$($adtSession.DirFiles)" -File -Recurse -ErrorAction SilentlyContinue

        $exePath32 = $files | Where-Object { $_.Name -match '7z.*\.exe' -and $_.Name -notmatch '7z.*x64\.exe' }
        $msiPath32 = $files | Where-Object { $_.Name -match '7z.*\.msi' -and $_.Name -notmatch '7z.*x64\.msi' }
        $mstPath32 = $files | Where-Object { $_.Name -match '7z.*\.mst' -and $_.Name -notmatch '7z.*x64\.mst' }

        if ($exePath32.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage 'Installing the 7-Zip application. Please Wait...'
            Start-ADTProcess -FilePath "$($exePath32.FullName)" -ArgumentList '/S' -WindowStyle 'Hidden'
            Start-Sleep -Seconds 5
        }
        elseif ($msiPath32.Count -gt 0 -and $mstPath32.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage 'Installing the 7-Zip application. Please Wait...'
            Start-ADTMsiProcess -Action Install -FilePath "$($msiPath32.FullName)" -Transforms "$($mstPath32.FullName)"
        }
        elseif ($msiPath32.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage 'Installing the 7-Zip application. Please Wait...'
            Start-ADTMsiProcess -Action Install -FilePath "$($msiPath32.FullName)"
        }
    }
    else {
        Write-ADTLogEntry -Message "Detected 64-bit OS Architecture" -Severity 1

        ## Install 7-Zip on 64-bit OS

        $files = Get-ChildItem -Path "$($adtSession.DirFiles)" -File -Recurse -ErrorAction SilentlyContinue

        $exePath64 = $files | Where-Object { $_.Name -match '7z.*x64\.exe' }
        $msiPath64 = $files | Where-Object { $_.Name -match '7z.*x64\.msi' }
        $mstPath64 = $files | Where-Object { $_.Name -match '7z.*x64\.mst' }
        $exePath32 = $files | Where-Object { $_.Name -match '7z.*\.exe' -and $_.Name -notmatch '7z.*x64\.exe' }
        $msiPath32 = $files | Where-Object { $_.Name -match '7z.*\.msi' -and $_.Name -notmatch '7z.*x64\.msi' }
        $mstPath32 = $files | Where-Object { $_.Name -match '7z.*\.mst' -and $_.Name -notmatch '7z.*x64\.mst' }

        if ($exePath64.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage 'Installing the 7-Zip (x64) application. Please Wait...'
            Start-ADTProcess -FilePath "$($exePath64.FullName)" -ArgumentList '/S' -WindowStyle 'Hidden'
            Start-Sleep -Seconds 5
        }
        elseif ($msiPath64.Count -gt 0 -and $mstPath64.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage 'Installing the 7-Zip (x64) application. Please Wait...'
            Start-ADTMsiProcess -Action Install -FilePath "$($msiPath64.FullName)" -Transforms "$($mstPath64.FullName)"
        }
        elseif ($msiPath64.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage 'Installing the 7-Zip (x64) application. Please Wait...'
            Start-ADTMsiProcess -Action Install -FilePath "$($msiPath64.FullName)"
        }
        elseif ($exePath32.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage 'Installing the 7-Zip (x86) application. Please Wait...'
            Start-ADTProcess -FilePath "$($exePath32.FullName)" -ArgumentList '/S' -WindowStyle 'Hidden'
            Start-Sleep -Seconds 5
        }
        elseif ($msiPath32.Count -gt 0 -and $mstPath32.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage 'Installing the 7-Zip (x86) application. Please Wait...'
            Start-ADTMsiProcess -Action Install -FilePath "$($msiPath32.FullName)" -Transforms "$($mstPath32.FullName)"
        }
        elseif ($msiPath32.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage 'Installing the 7-Zip (x86) application. Please Wait...'
            Start-ADTMsiProcess -Action Install -FilePath "$($msiPath32.FullName)"
        }      
    }

    ##================================================
    ## MARK: Post-Install
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

}

New-Item -Path "C:\ProgramData\VACO\InstalledApps\7-zip_2501.tag" -ItemType File -Force

function Uninstall-ADTDeployment
{
    ##================================================
    ## MARK: Pre-Uninstall
    ##================================================
    $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

    ## Show Welcome Message, close 7-Zip with a 60 second countdown before automatically closing.
    Show-ADTInstallationWelcome -CloseProcesses 7z,7zFM -CloseProcessesCountdown 60

    ## Show Progress Message (with a message to indicate the application is being uninstalled).
    Show-ADTInstallationProgress -StatusMessage 'Removing Any Existing Versions of 7-Zip. Please Wait...'
  
    ##================================================
    ## MARK: Uninstall
    ##================================================
    $adtSession.InstallPhase = $adtSession.DeploymentType

    ## Uninstall Any Existing Versions of 7-Zip (MSI)
    Uninstall-ADTApplication -Name '7-Zip' -ApplicationType 'MSI'

    ## Uninstall Any Existing Versions of 7-Zip (EXE)
    Uninstall-ADTApplication -Name '7-Zip' -ApplicationType 'EXE' -ArgumentList '/S'

    ##================================================
    ## MARK: Post-Uninstallation
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

    ## <Perform Post-Uninstallation tasks here>
}

function Repair-ADTDeployment
{
    ##================================================
    ## MARK: Pre-Repair
    ##================================================
    $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

    ## Show Welcome Message, close 7-Zip with a 60 second countdown before automatically closing.
    Show-ADTInstallationWelcome -CloseProcesses 7z,7zFM -CloseProcessesCountdown 60

    ## Show Progress Message (with the default message).
    Show-ADTInstallationProgress
 
    ##================================================
    ## MARK: Repair
    ##================================================
    $adtSession.InstallPhase = $adtSession.DeploymentType

    ## Handle Zero-Config MSI repairs.
    if ($adtSession.UseDefaultMsi)
    {
        $ExecuteDefaultMSISplat = @{ Action = $adtSession.DeploymentType; FilePath = $adtSession.DefaultMsiFile }
        if ($adtSession.DefaultMstFile)
        {
            $ExecuteDefaultMSISplat.Add('Transform', $adtSession.DefaultMstFile)
        }
        Start-ADTMsiProcess @ExecuteDefaultMSISplat
    }
  
    ##================================================
    ## MARK: Post-Repair
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

    ## <Perform Post-Repair tasks here>
}


##================================================
## MARK: Initialization
##================================================

# Set strict error handling across entire operation.
$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue
Set-StrictMode -Version 1

# Import the module and instantiate a new session.
try
{
    $moduleName = if ([System.IO.File]::Exists("$PSScriptRoot\PSAppDeployToolkit\PSAppDeployToolkit.psd1"))
    {
        Get-ChildItem -LiteralPath $PSScriptRoot\PSAppDeployToolkit -Recurse -File | Unblock-File -ErrorAction Ignore
        "$PSScriptRoot\PSAppDeployToolkit\PSAppDeployToolkit.psd1"
    }
    else
    {
        'PSAppDeployToolkit'
    }
    Import-Module -FullyQualifiedName @{ ModuleName = $moduleName; Guid = '8c3c366b-8606-4576-9f2d-4051144f7ca2'; ModuleVersion = '4.0.6' } -Force
    try
    {
        $iadtParams = Get-ADTBoundParametersAndDefaultValues -Invocation $MyInvocation
        $adtSession = Open-ADTSession -SessionState $ExecutionContext.SessionState @adtSession @iadtParams -PassThru
    }
    catch
    {
        Remove-Module -Name PSAppDeployToolkit* -Force
        throw
    }
}
catch
{
    $Host.UI.WriteErrorLine((Out-String -InputObject $_ -Width ([System.Int32]::MaxValue)))
    exit 60008
}


##================================================
## MARK: Invocation
##================================================

try
{
    Get-Item -Path $PSScriptRoot\PSAppDeployToolkit.* | & {
        process
        {
            Get-ChildItem -LiteralPath $_.FullName -Recurse -File | Unblock-File -ErrorAction Ignore
            Import-Module -Name $_.FullName -Force
        }
    }
    & "$($adtSession.DeploymentType)-ADTDeployment"
    Close-ADTSession
}
catch
{
    Write-ADTLogEntry -Message ($mainErrorMessage = Resolve-ADTErrorRecord -ErrorRecord $_) -Severity 3
    Show-ADTDialogBox -Text $mainErrorMessage -Icon Stop | Out-Null
    Close-ADTSession -ExitCode 60001
}
finally
{
    Remove-Module -Name PSAppDeployToolkit* -Force
}