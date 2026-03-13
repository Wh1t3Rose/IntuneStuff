<#

.SYNOPSIS
PSAppDeployToolkit - This script performs the installation or uninstallation of an application(s).

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

# Script variables.
$DeployAppScriptFriendlyName = $MyInvocation.MyCommand.Name
$DeployAppScriptParameters = $PSBoundParameters
$DeployAppScriptVersion = '4.1.6'

# Must be set outside of the adtSession for varable support in AppProcessesToClose
$InstallName  = 'sqldeveloper'
$ProcessName  = 'sqldeveloper'

# Zero-Config MSI support is provided when "AppName" is null or empty.
# By setting the "AppName" property, Zero-Config MSI will be disabled.
$adtSession = @{
    # App variables.
    # App variables.
    AppVendor = ''
    AppName = 'WinSCP'
    AppVersion = ''
    AppArch = ''
    AppLang = 'EN'
    AppRevision = '01'
    AppSuccessExitCodes = @(0)
    AppRebootExitCodes = @(1641, 3010)
    InstallName = $InstallName
    AppProcessesToClose = @( @{ Name = $ProcessName; Description = $InstallName } )    
    AppScriptVersion = '1.0.0'
    AppScriptDate = '2026-01-21'
    AppScriptAuthor = '<Tyler Cox>'
    RequireAdmin = $false

    # Messaging placeholders
    InstallWelcomeMessage   = ''
    UninstallWelcomeMessage = ''
    CompletionMessage       = ''

    # Tagging
    TagRoot = 'C:\ProgramData\VACO\InstalledApps'
    TagName = $InstallName.tag
}


##================================================
## MARK: EXE Installer Configuration
##================================================

# Installer file names (define here; full paths resolved at runtime after PSADT session opens)
$ExeInstallerName   = 'WinSCP-6.5.5-Setup.exe'
$ExeUninstallerName = 'WinSCP-6.5.5-Setup.exe'
# Optional: provide a full path to the uninstaller to override the files folder.
# Example: $ExeUninstallerPath = 'C:\Program Files\Git\unins000.exe'
$ExeUninstallerPath = 'C:\Program Files (x86)\WinSCP\unins000.exe'

# Arguments for EXE installation
# Use double quotes so the installer log path expands `$InstallName` at runtime
$ExeInstallArgs = "/VERYSILENT /NORESTART /LOG=`"C:\Windows\Logs\Software\$InstallName.log`""

# Arguments for EXE uninstallation
$ExeUninstallArgs = "/VERYSILENT /NORESTART /LOG=`"C:\Windows\Logs\Software\$InstallName.log`""

# Zip File Extraction
# Resolve these at runtime after the PSADT session opens. Keep names here for configuration.
$ZipName    = 'sqldeveloper-24.3.1.347.1826-x64.zip'
$ZipPath    = '$($adtSession.DirFiles)\'
$TargetPath = 'env:ProgramFiles\$InstallName'

# Script variables.
$DeployAppScriptFriendlyName = $MyInvocation.MyCommand.Name
$DeployAppScriptParameters = $PSBoundParameters
$DeployAppScriptVersion = '4.1.6'


# --- Messaging ---
if (-not $adtSession.InstallWelcomeMessage) {
    $adtSession.InstallWelcomeMessage =
        "Setup will install $($adtSession.InstallName). Please save your work before continuing."
}

if (-not $adtSession.UninstallWelcomeMessage) {
    $adtSession.UninstallWelcomeMessage =
        "$($adtSession.InstallName) will be removed from this device."
}

if (-not $adtSession.CompletionMessage) {
    $adtSession.CompletionMessage =
        "$($adtSession.InstallName) has been successfully installed."
}

# --- Tagging ---
if (-not $adtSession.TagName) {
    $adtSession.TagName = "$($adtSession.InstallName).tag"
}

$adtSession.TagFullPath = Join-Path $adtSession.TagRoot $adtSession.TagName

##================================================
## MARK: Derived Runtime Wiring
##================================================

# --- Process closing (window title–based) ---
if ($adtSession.EnableProcessClose) {

    if ($adtSession.ProcessOverride.Count -gt 0) {
        $adtSession.AppProcessesToClose = $adtSession.ProcessOverride
    }
    else {
        $adtSession.AppProcessesToClose = @(
            @{
                Name        = $adtSession.InstallName
                Description = $adtSession.InstallName
            }
        )
    }
}


# --------------------------------------------------------------------------------------------------------#

##================================================
## MARK: Deployment Functions
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

    $saiwParams = @{
        AllowDefer     = $true
        DeferTimes     = 3
        CheckDiskSpace = $true
        PersistPrompt  = $true
    }

    if ($adtSession.EnableProcessClose -and $adtSession.AppProcessesToClose.Count -gt 0) {
        $saiwParams.CloseProcesses = $adtSession.AppProcessesToClose
    }

    if ($adtSession.EnableWelcomePrompt) {
        Show-ADTInstallationWelcome @saiwParams
    }

    Show-ADTInstallationProgress

    ## <Perform Pre-Installation tasks here>

    if (-not (Test-Path $adtSession.TagRoot)) {
    New-Item -Path $adtSession.TagRoot -ItemType Directory -Force | Out-Null
    }

    New-Item -Path $adtSession.TagFullPath -ItemType File -Force | Out-Null

    Write-ADTLogEntry -Message "Created install tag: $($adtSession.TagName)"


    ##================================================
    ## MARK: Install
    ##================================================
    $adtSession.InstallPhase = $adtSession.DeploymentType

    ## Handle Zero-Config MSI installations.
    if ($adtSession.UseDefaultMsi)
    {
        $ExecuteDefaultMSISplat = @{ Action = $adtSession.DeploymentType; FilePath = $adtSession.DefaultMsiFile }
        if ($adtSession.DefaultMstFile)
        {
            $ExecuteDefaultMSISplat.Add('Transforms', $adtSession.DefaultMstFile)
        }
        Start-ADTMsiProcess @ExecuteDefaultMSISplat
        if ($adtSession.DefaultMspFiles)
        {
            $adtSession.DefaultMspFiles | Start-ADTMsiProcess -Action Patch
        }
    }

    ## <Perform Installation tasks here>
        # Ensure EXE installer/uninstaller variables are initialized to $null if not defined (for MSI fallback)
        if (-not (Get-Variable -Name 'ExeInstallerName' -Scope Script -ErrorAction SilentlyContinue)) { $ExeInstallerName = $null }
        if (-not (Get-Variable -Name 'ExeInstallArgs' -Scope Script -ErrorAction SilentlyContinue)) { $ExeInstallArgs = $null }
        if (-not (Get-Variable -Name 'ExeUninstallerName' -Scope Script -ErrorAction SilentlyContinue)) { $ExeUninstallerName = $null }
        if (-not (Get-Variable -Name 'ExeUninstallArgs' -Scope Script -ErrorAction SilentlyContinue)) { $ExeUninstallArgs = $null }
        if (-not (Get-Variable -Name 'ExeUninstallerPath' -Scope Script -ErrorAction SilentlyContinue)) { $ExeUninstallerPath = $null }
    # Resolve installer path at runtime using $adtSession.DirFiles (populated by PSADT)
    #$ExeInstallerPath = "$($adtSession.DirFiles)\$ExeInstallerName"

    # Resolve ZIP and target paths at runtime using $adtSession.DirFiles
    $ZipPath = "$($adtSession.DirFiles)\$ZipName"
    $TargetPath = Join-Path $env:ProgramFiles $InstallName

    # Ensure the installer log folder exists so Inno Setup can create the log file
    $adtLogDir = 'C:\Windows\Logs\Software'
    if (-not (Test-Path -LiteralPath $adtLogDir)) {
        New-Item -Path $adtLogDir -ItemType Directory -Force | Out-Null
    }

    # Verify ZIP exists before attempting to extract
    if (-not (Test-Path -LiteralPath $ZipPath)) {
        Write-ADTLogEntry -Message "ZIP missing: $ZipPath" -Severity 3
        Show-ADTInstallationPrompt -Message "ZIP missing: $ZipPath" -Icon Error -ButtonRightText 'OK' -NoWait
        Close-ADTSession -ExitCode 69003
    }

    If (-not (Test-Path $TargetPath)) {
        New-Item -Path $TargetPath -ItemType Directory -Force | Out-Null
    }

    Expand-Archive -Path $ZipPath -DestinationPath $TargetPath -Force

    # Start-ADTProcess -FilePath $ExeInstallerPath -ArgumentList $ExeInstallArgs


    ##================================================
    ## MARK: Post-Install
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

    ## <Perform Post-Installation tasks here>

    $ExePath      = "$env:ProgramFiles\$InstallName\$InstallName\$InstallName.exe"

    # Create an All Users Start Menu shortcut
    $startMenuRoot = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
    $startMenuFolder = Join-Path $startMenuRoot $InstallName
    if (-not (Test-Path -LiteralPath $startMenuFolder)) {
        New-Item -Path $startMenuFolder -ItemType Directory -Force | Out-Null
    }
    $startMenuShortcut = Join-Path $startMenuFolder "$InstallName.lnk"
    New-ADTShortcut -LiteralPath $startMenuShortcut -TargetPath $ExePath -WorkingDirectory (Split-Path $ExePath) -Description "$InstallName"

    # Create a Public Desktop shortcut and copy it into each user's Desktop folder
    $publicDesktop = Join-Path $env:Public 'Desktop'
    $publicShortcut = Join-Path $publicDesktop "$InstallName.lnk"
    if (-not (Test-Path -LiteralPath $publicDesktop)) {
        New-Item -Path $publicDesktop -ItemType Directory -Force | Out-Null
    }
    New-ADTShortcut -LiteralPath $publicShortcut -TargetPath $ExePath -WorkingDirectory (Split-Path $ExePath) -Description "$InstallName"

    try {
        Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.Name
            if ($name -in @('Public','Default','Default User','All Users','DefaultAppPool','DefaultAccount')) { return }
            $userDesktop = Join-Path $_.FullName 'Desktop'
            if (Test-Path -LiteralPath $userDesktop) {
                $dest = Join-Path $userDesktop "$InstallName.lnk"
                try {
                    Copy-Item -LiteralPath $publicShortcut -Destination $dest -Force -ErrorAction Stop
                    Write-ADTLogEntry -Message "Copied shortcut to user desktop: $dest"
                }
                catch {
                    Write-ADTLogEntry -Message "Failed to copy shortcut to $($userDesktop): $($_.Exception.Message)" -Severity 2
                }
            }
        }
    }
    catch {
        Write-ADTLogEntry -Message "Could not enumerate C:\\Users: $($_.Exception.Message)" -Severity 2
    }

    # (Pin-to-taskbar functionality removed — not reliable across Windows versions)


    ## Display a message at the end of the install.
    if ($adtSession.EnableCompletionPrompt -and -not $adtSession.UseDefaultMsi) {
        Show-ADTInstallationPrompt `
            -Message $adtSession.CompletionMessage `
            -ButtonRightText 'OK' `
            -Icon Information `
            -NoWait
    }

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


# Close-app dialog
Show-ADTInstallationWelcome `
    -CloseProcesses $adtSession.AppProcessesToClose `
    -CloseProcessesCountdown 60

    Show-ADTInstallationProgress
    ## <Perform Pre-Uninstallation tasks here>

    ##================================================
    ## MARK: Uninstall
    ##================================================
    $adtSession.InstallPhase = $adtSession.DeploymentType

    ## Handle Zero-Config MSI uninstallations.
    if ($adtSession.UseDefaultMsi)
    {
        $ExecuteDefaultMSISplat = @{ Action = $adtSession.DeploymentType; FilePath = $adtSession.DefaultMsiFile }
        if ($adtSession.DefaultMstFile)
        {
            $ExecuteDefaultMSISplat.Add('Transforms', $adtSession.DefaultMstFile)
        }
        Start-ADTMsiProcess @ExecuteDefaultMSISplat
    }

    ## <Perform Uninstallation tasks here>
        # Ensure EXE uninstaller variables are initialized to $null if not defined (for MSI fallback)
        if (-not (Get-Variable -Name 'ExeUninstallerResolved' -Scope Script -ErrorAction SilentlyContinue)) { $ExeUninstallerResolved = $null }
        if (-not (Get-Variable -Name 'ExeUninstallerName' -Scope Script -ErrorAction SilentlyContinue)) { $ExeUninstallerName = $null }
        if (-not (Get-Variable -Name 'ExeUninstallArgs' -Scope Script -ErrorAction SilentlyContinue)) { $ExeUninstallArgs = $null }
        if (-not (Get-Variable -Name 'ExeUninstallerPath' -Scope Script -ErrorAction SilentlyContinue)) { $ExeUninstallerPath = $null }
        if (-not (Get-Variable -Name 'ExeInstallerName' -Scope Script -ErrorAction SilentlyContinue)) { $ExeInstallerName = $null }
        if (-not (Get-Variable -Name 'ExeInstallArgs' -Scope Script -ErrorAction SilentlyContinue)) { $ExeInstallArgs = $null }

        # Resolve uninstaller path at runtime using $adtSession.DirFiles (populated by PSADT)
    #$ExeUninstallerPath = "$($adtSession.DirFiles)\$ExeUninstallerName"

        # Log what we are about to do
        Write-ADTLogEntry -Message "Starting Uninstallation: $ExeUninstallerPath with arguments: $ExeUninstallArgs"

        # Ensure the installer log folder exists so Inno Setup can create the log file
        $adtLogDir = 'C:\Windows\Logs\Software'
        if (-not (Test-Path -LiteralPath $adtLogDir)) {
            New-Item -Path $adtLogDir -ItemType Directory -Force | Out-Null
        }

        # Execute the EXE uninstaller with the arguments from the variables section
        #Start-ADTProcess -FilePath $ExeUninstallerPath -ArgumentList $ExeUninstallArgs

        # Cleanup installed files and shortcuts
        try {
            $installPath = Join-Path $env:ProgramFiles $InstallName
            if (Test-Path -LiteralPath $installPath) {
                Remove-Item -LiteralPath $installPath -Recurse -Force -ErrorAction Stop
                Write-ADTLogEntry -Message "Removed install folder: $installPath"
            }

            # Remove All Users Start Menu folder
            $startMenuRoot = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs'
            $startMenuFolder = Join-Path $startMenuRoot $InstallName
            if (Test-Path -LiteralPath $startMenuFolder) {
                Remove-Item -LiteralPath $startMenuFolder -Recurse -Force -ErrorAction Stop
                Write-ADTLogEntry -Message "Removed Start Menu folder: $startMenuFolder"
            }

            # Remove Public Desktop shortcut if present
            $publicShortcut = Join-Path $env:Public "Desktop\$InstallName.lnk"
            if (Test-Path -LiteralPath $publicShortcut) {
                Remove-Item -LiteralPath $publicShortcut -Force -ErrorAction Stop
                Write-ADTLogEntry -Message "Removed public desktop shortcut: $publicShortcut"
            }
        }
        catch {
            Write-ADTLogEntry -Message "Cleanup failed: $($_.Exception.Message)" -Severity 2
        }
    
    ## Start-ADTProcess -FilePath (Join-Path $env:ProgramFiles 'ProgramName\uninstall.exe') -ArgumentList '/S'

    ### Start-ADTProcess -FilePath Files\Installer.exe' -ArgumentList '/S'

    ##================================================
    ## MARK: Post-Uninstallation
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

    ## <Perform Post-Uninstallation tasks here>

    if (Test-Path $adtSession.TagFullPath) {
    Remove-Item -Path $adtSession.TagFullPath -Force
    Write-ADTLogEntry -Message "Removed install tag: $($adtSession.TagName)"
}

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

    ## If there are processes to close, show Welcome Message with a 60 second countdown before automatically closing.
    if ($adtSession.AppProcessesToClose.Count -gt 0)
    {
        Show-ADTInstallationWelcome -CloseProcesses $adtSession.AppProcessesToClose -CloseProcessesCountdown 60
    }

    ## Show Progress Message (with the default message).
    Show-ADTInstallationProgress

    ## <Perform Pre-Repair tasks here>


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
            $ExecuteDefaultMSISplat.Add('Transforms', $adtSession.DefaultMstFile)
        }
        Start-ADTMsiProcess @ExecuteDefaultMSISplat
    }

    ## <Perform Repair tasks here>


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
    # Import the module locally if available, otherwise try to find it from PSModulePath.
    if (Test-Path -LiteralPath "$PSScriptRoot\PSAppDeployToolkit\PSAppDeployToolkit.psd1" -PathType Leaf)
    {
        Get-ChildItem -LiteralPath "$PSScriptRoot\PSAppDeployToolkit" -Recurse -File | Unblock-File -ErrorAction Ignore
        Import-Module -FullyQualifiedName @{ ModuleName = "$PSScriptRoot\PSAppDeployToolkit\PSAppDeployToolkit.psd1"; Guid = '8c3c366b-8606-4576-9f2d-4051144f7ca2'; ModuleVersion = '4.1.6' } -Force
    }
    else
    {
        Import-Module -FullyQualifiedName @{ ModuleName = 'PSAppDeployToolkit'; Guid = '8c3c366b-8606-4576-9f2d-4051144f7ca2'; ModuleVersion = '4.1.6' } -Force
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
    # Show-ADTInstallationPrompt -Message "$($adtSession.DeploymentType) failed at line $($_.InvocationInfo.ScriptLineNumber), char $($_.InvocationInfo.OffsetInLine):`n$($_.InvocationInfo.Line.Trim())`n`nMessage:`n$($_.Exception.Message)" -ButtonRightText OK -Icon Error -NoWait

    Close-ADTSession -ExitCode 60001
}

