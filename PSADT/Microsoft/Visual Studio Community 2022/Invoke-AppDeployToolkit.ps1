<#

.SYNOPSIS
PSAppDeployToolkit - This script performs the installation or uninstallation of Visual Studio Community 2022.

.DESCRIPTION
- The script is provided as a template to perform an install, uninstall, or repair of an application(s).
- The script either performs an "Install", "Uninstall", or "Repair" deployment type.
- The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.

The script imports the PSAppDeployToolkit module which contains the logic and functions required to install or uninstall an application.

.PARAMETER DeploymentType
The type of deployment to perform.

.PARAMETER DeployMode
Specifies whether the installation should be run in Interactive (shows dialogs), Silent (no dialogs), NonInteractive (dialogs without prompts) mode, or Auto (shows dialogs if a user is logged on, device is not in the OOBE, and there's no running apps to close).

Silent mode is automatically set if it is detected that the process is not user interactive, no users are logged on, the device is in Autopilot mode, or there's specified processes to close that are currently running.

.PARAMETER SuppressRebootPassThru
Suppresses the 3010 return code (requires restart) from being passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.

.PARAMETER TerminalServerMode
Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Desktop Session Hosts/Citrix servers.

.PARAMETER DisableLogging
Disables logging to file for the script.

.EXAMPLE
powershell.exe -File Invoke-AppDeployToolkit.ps1

.EXAMPLE
powershell.exe -File Invoke-AppDeployToolkit.ps1 -DeployMode Silent

.EXAMPLE
powershell.exe -File Invoke-AppDeployToolkit.ps1 -DeploymentType Uninstall

.EXAMPLE
Invoke-AppDeployToolkit.exe -DeploymentType Install -DeployMode Silent

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
    # Default is 'Install'.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Install', 'Uninstall', 'Repair')]
    [System.String]$DeploymentType,

    # Default is 'Auto'. Don't hard-code this unless required.
    [Parameter(Mandatory = $false)]
    [ValidateSet('Auto', 'Interactive', 'NonInteractive', 'Silent')]
    [System.String]$DeployMode,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$SuppressRebootPassThru,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$TerminalServerMode,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.SwitchParameter]$DisableLogging
)


##================================================
## MARK: Variables
##================================================

# Zero-Config MSI support is provided when "AppName" is null or empty.
# By setting the "AppName" property, Zero-Config MSI will be disabled.
$adtSession = @{
    # App variables.
    AppVendor = 'Microsoft Corporation'
    AppName = 'Visual Studio Community 2022'
    AppVersion = ''
    AppArch = ''
    AppLang = 'EN'
    AppRevision = '01'
    AppSuccessExitCodes = @(0)
    AppRebootExitCodes = @(1641, 3010)
    AppProcessesToClose = @(@{ Name = 'devenv'; Description = 'Visual Studio Community 2022' })
    AppScriptVersion = '1.0.0'
    AppScriptDate = '2025-11-10'
    AppScriptAuthor = 'Jason Bergner'
    RequireAdmin = $true

    # Install Titles (Only set here to override defaults set by the toolkit).
    InstallName = ''
    InstallTitle = ''

    # Script variables.
    DeployAppScriptFriendlyName = $MyInvocation.MyCommand.Name
    DeployAppScriptParameters = $PSBoundParameters
    DeployAppScriptVersion = '4.1.3'
}

function Install-ADTDeployment
{
    [CmdletBinding()]
    param
    (
    )

    ##================================================
    ## MARK: Pre-Install
    ##================================================
    $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

    ## Show Welcome Message, close processes with a 60 second countdown before automatically closing. 
    ## Switch to $true to allow up to 3 deferrals, verify there is enough disk space to complete the install, and persist the prompt.
    $saiwParams = @{
        CloseProcessesCountdown = 60
        AllowDefer = $false
        DeferTimes = 3
        CheckDiskSpace = $false
        PersistPrompt = $false
    }
    if ($adtSession.AppProcessesToClose.Count -gt 0)
    {
        $saiwParams.Add('CloseProcesses', $adtSession.AppProcessesToClose)
    }
    Show-ADTInstallationWelcome @saiwParams

    ##================================================
    ## MARK: Install
    ##================================================
    $adtSession.InstallPhase = $adtSession.DeploymentType

    ## Perform Install or Update Visual Studio Community 2022
    $files = Get-ChildItem -Path "$($adtSession.DirFiles)" -File -Recurse -ErrorAction SilentlyContinue
    $exePath = $files | Where-Object { $_.Name -eq 'vs_Community.exe' -and ($_.VersionInfo.ProductVersion -eq 'Visual Studio 2022') }

    if ($exePath.Count -gt 0) {

        ## Check if Visual Studio Community 2022 is already installed
        $appName = Get-ADTApplication -Name 'Visual Studio Community 2022'

        if ($appName.Count -gt 0) {
            Show-ADTInstallationProgress -StatusMessage "Updating $($adtSession.AppName). Please Wait..."
            Start-ADTProcess -FilePath "$($exePath.FullName)" -ArgumentList 'update --quiet --norestart --wait' -WindowStyle 'Hidden'
            Start-Sleep -Seconds 5
        }
        else {
            Show-ADTInstallationProgress -StatusMessage "Installing $($adtSession.AppName). Please Wait..."
            Start-ADTProcess -FilePath "$($exePath.FullName)" -ArgumentList '--quiet --norestart --wait' -WindowStyle 'Hidden'
            Start-Sleep -Seconds 5
        }
    }
    else {
        Write-ADTLogEntry -Message "$($adtSession.AppName) installer was not found. Installation aborted." -Severity 2
        Show-ADTInstallationPrompt -Message "$($adtSession.AppName) installer was not found. Installation aborted." -ButtonRightText 'OK'
    } 

    ##================================================
    ## MARK: Post-Install
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

}

function Uninstall-ADTDeployment
{
    [CmdletBinding()]
    param
    (
    )

    ##================================================
    ## MARK: Pre-Uninstall
    ##================================================
    $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

    ## If there are processes to close, show Welcome Message with a 60 second countdown before automatically closing.
    if ($adtSession.AppProcessesToClose.Count -gt 0)
    {
        Show-ADTInstallationWelcome -CloseProcesses $adtSession.AppProcessesToClose -CloseProcessesCountdown 60
    }

    ## Show Progress Message (with a message to indicate the application is being uninstalled).
    Show-ADTInstallationProgress -StatusMessage "Uninstalling Any Existing Version of $($adtSession.AppName). Please Wait..."

    ##================================================
    ## MARK: Uninstall
    ##================================================
    $adtSession.InstallPhase = $adtSession.DeploymentType

    ## Uninstall Any Existing Version of Visual Studio Community 2022 (EXE)
    $appName = Get-ADTApplication -Name 'Visual Studio Community 2022'

    if ($appName.Count -gt 0) {
        Uninstall-ADTApplication -Name 'Visual Studio Community 2022' -ApplicationType 'EXE' -AdditionalArgumentList '--quiet --norestart' -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
    }
    else {
        Write-ADTLogEntry -Message "$($adtSession.AppName) was not found." -Severity 1
    }

    ## Uninstall Any Existing Version of Microsoft Visual Studio Installer (EXE)
    Write-ADTLogEntry -Message "Starting Visual Studio Installer cleanup routine..." -Severity 1

    ## Attempt to read the install path from registry manually
    $vsInstallerRegPaths = @(
        'HKLM:\SOFTWARE\Microsoft\VisualStudio\Setup',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\Setup'
    )

    $installPath = $null

    foreach ($regPath in $vsInstallerRegPaths) {
        try {
            $candidate = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).InstallDir
            if ($candidate -and (Test-Path $candidate)) {
                $installPath = $candidate
                break
            }
        }
        catch {
            Write-ADTLogEntry -Message "Failed to read registry key: $regPath" -Severity 2
        }
    }

    ## If not found in registry, fallback to common default location
    if (-not $installPath) {
        $defaultPaths = @(
            'C:\Program Files (x86)\Microsoft Visual Studio\Installer',
            'C:\Program Files\Microsoft Visual Studio\Installer'
        )

        foreach ($path in $defaultPaths) {
            if (Test-Path $path) {
                $installPath = $path
                break
            }
        }
    }

    if ($installPath) {
        $cleanupExe = Join-Path -Path $installPath -ChildPath 'InstallCleanup.exe'

        if (Test-Path $cleanupExe) {
            Write-ADTLogEntry -Message "Running InstallCleanup.exe from: $cleanupExe" -Severity 1
            try {
                Start-ADTProcess -FilePath $cleanupExe -ArgumentList '-full' -WindowStyle 'Hidden' -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
                Write-ADTLogEntry -Message "Visual Studio cleanup completed successfully." -Severity 1
            }
            catch {
                Write-ADTLogEntry -Message "Failed to run InstallCleanup.exe. Error: $($_.Exception.Message)" -Severity 2
            }
        }
        else {
            Write-ADTLogEntry -Message "InstallCleanup.exe not found at expected path: $cleanupExe" -Severity 2
        }
    }
    else {
        Write-ADTLogEntry -Message "Microsoft Visual Studio Installer not found on this system." -Severity 1
    }

    ##================================================
    ## MARK: Post-Uninstallation
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

}

function Repair-ADTDeployment
{
    [CmdletBinding()]
    param
    (
    )

    ##================================================
    ## MARK: Pre-Repair
    ##================================================
    $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

    ##================================================
    ## MARK: Repair
    ##================================================
    $adtSession.InstallPhase = $adtSession.DeploymentType

    ##================================================
    ## MARK: Post-Repair
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

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
    # Import the module locally if available, otherwise try to find it from PSModulePath.
    if (Test-Path -LiteralPath "$PSScriptRoot\PSAppDeployToolkit\PSAppDeployToolkit.psd1" -PathType Leaf)
    {
        Get-ChildItem -LiteralPath "$PSScriptRoot\PSAppDeployToolkit" -Recurse -File | Unblock-File -ErrorAction Ignore
        Import-Module -FullyQualifiedName @{ ModuleName = "$PSScriptRoot\PSAppDeployToolkit\PSAppDeployToolkit.psd1"; Guid = '8c3c366b-8606-4576-9f2d-4051144f7ca2'; ModuleVersion = '4.1.3' } -Force
    }
    else
    {
        Import-Module -FullyQualifiedName @{ ModuleName = 'PSAppDeployToolkit'; Guid = '8c3c366b-8606-4576-9f2d-4051144f7ca2'; ModuleVersion = '4.1.3' } -Force
    }

    # Open a new deployment session, replacing $adtSession with a DeploymentSession.
    $iadtParams = Get-ADTBoundParametersAndDefaultValues -Invocation $MyInvocation
    $adtSession = Remove-ADTHashtableNullOrEmptyValues -Hashtable $adtSession
    $adtSession = Open-ADTSession @adtSession @iadtParams -PassThru
}
catch
{
    $Host.UI.WriteErrorLine((Out-String -InputObject $_ -Width ([System.Int32]::MaxValue)))
    exit 60008
}


##================================================
## MARK: Invocation
##================================================

# Commence the actual deployment operation.
try
{
    # Import any found extensions before proceeding with the deployment.
    Get-ChildItem -LiteralPath $PSScriptRoot -Directory | & {
        process
        {
            if ($_.Name -match 'PSAppDeployToolkit\..+$')
            {
                Get-ChildItem -LiteralPath $_.FullName -Recurse -File | Unblock-File -ErrorAction Ignore
                Import-Module -Name $_.FullName -Force
            }
        }
    }

    # Invoke the deployment and close out the session.
    & "$($adtSession.DeploymentType)-ADTDeployment"
    Close-ADTSession
}
catch
{
    # An unhandled error has been caught.
    $mainErrorMessage = "An unhandled error within [$($MyInvocation.MyCommand.Name)] has occurred.`n$(Resolve-ADTErrorRecord -ErrorRecord $_)"
    Write-ADTLogEntry -Message $mainErrorMessage -Severity 3

    ## Error details hidden from the user by default. Show a simple dialog with full stack trace:
    # Show-ADTDialogBox -Text $mainErrorMessage -Icon Stop -NoWait

    ## Or, a themed dialog with basic error message:
    # Show-ADTInstallationPrompt -Message "$($adtSession.DeploymentType) failed at line $($_.InvocationInfo.ScriptLineNumber), char $($_.InvocationInfo.OffsetInLine):`n$($_.InvocationInfo.Line.Trim())`n`nMessage:`n$($_.Exception.Message)" -MessageAlignment Left -ButtonRightText OK -Icon Error -NoWait

    Close-ADTSession -ExitCode 60001
}