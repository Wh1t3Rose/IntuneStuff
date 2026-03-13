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
$InstallName  = 'SQL WorkBench'
$ProcessName  = 'SQLWorkbench.exe'

# Zero-Config MSI support is provided when "AppName" is null or empty.
# By setting the "AppName" property, Zero-Config MSI will be disabled.
$adtSession = @{
    # App variables.
    # App variables.
    AppVendor = ''
    AppName = ''
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

    # Tagging
    TagRoot = 'C:\ProgramData\VACO\InstalledApps'
    TagName = $InstallName.tag
}


##================================================
## MARK: EXE Installer Configuration
##================================================

# Installer file names (define here; full paths resolved at runtime after PSADT session opens)
# $ExeInstallerName   = 'dbeaver-ce-25.3.3-x86_64-setup.exe'
# $ExeUninstallerName = 'Uninstall.exe'
# Optional: provide a full path to the uninstaller to override the files folder.
# Example: $ExeUninstallerPath = 'C:\Program Files\Git\unins000.exe'
# $ExeUninstallerPath = 'C:\Program Files\DBeaver\'

# Arguments for EXE installation
# Use double quotes so the installer log path expands `$InstallName` at runtime
# $ExeInstallArgs = "/S /allusers /LOG=`"C:\Windows\Logs\Software\$InstallName.log`""

# Arguments for EXE uninstallation
# $ExeUninstallArgs = "/S /allusers /LOG=`"C:\Windows\Logs\Software\$InstallName.log`""

# Script variables.
$DeployAppScriptFriendlyName = $MyInvocation.MyCommand.Name
$DeployAppScriptParameters = $PSBoundParameters
$DeployAppScriptVersion = '4.1.6'


# --- Tagging ---
if (-not $adtSession.TagName) {
    $adtSession.TagName = "$($adtSession.InstallName).tag"
}

$adtSession.TagFullPath = Join-Path $adtSession.TagRoot $adtSession.TagName

# --- Messaging (standard defaults) ---
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
    # If an EXE installer filename is provided, run it. Otherwise fall back to Zero-Config MSI.
    if (-not [string]::IsNullOrWhiteSpace($ExeInstallerName)) {
        # Resolve installer path at runtime using $adtSession.DirFiles (populated by PSADT)
        $ExeInstallerPath = Join-Path -Path $adtSession.DirFiles -ChildPath $ExeInstallerName

        # Verify installer exists before attempting to run it
        if (-not (Test-Path -LiteralPath $ExeInstallerPath)) {
            Write-ADTLogEntry -Message "Installer missing: $ExeInstallerPath" -Severity 3
            Show-ADTInstallationPrompt -Message "Installer missing: $ExeInstallerPath" -ButtonRightText 'OK' -Icon Error -NoWait
            Close-ADTSession -ExitCode 69001
        }

        # Ensure the installer log folder exists so installers can create the log file
        $adtLogDir = 'C:\Windows\Logs\Software'
        if (-not (Test-Path -LiteralPath $adtLogDir)) {
            New-Item -Path $adtLogDir -ItemType Directory -Force | Out-Null
        }

        Start-ADTProcess -FilePath $ExeInstallerPath -ArgumentList $ExeInstallArgs
    }
    else {
        Write-ADTLogEntry -Message "No EXE installer specified (\$ExeInstallerName is empty). Falling back to Zero-Config MSI if available."

        if ($adtSession.DefaultMsiFile) {
            $ExecuteDefaultMSISplat = @{ Action = $adtSession.DeploymentType; FilePath = $adtSession.DefaultMsiFile }
            if ($adtSession.DefaultMstFile) {
                $ExecuteDefaultMSISplat.Add('Transforms', $adtSession.DefaultMstFile)
            }
            Start-ADTMsiProcess @ExecuteDefaultMSISplat
            if ($adtSession.DefaultMspFiles) {
                $adtSession.DefaultMspFiles | Start-ADTMsiProcess -Action Patch
            }
        }
        elseif ($adtSession.UseDefaultMsi) {
            $ExecuteDefaultMSISplat = @{ Action = $adtSession.DeploymentType; FilePath = $adtSession.DefaultMsiFile }
            if ($adtSession.DefaultMstFile) {
                $ExecuteDefaultMSISplat.Add('Transforms', $adtSession.DefaultMstFile)
            }
            Start-ADTMsiProcess @ExecuteDefaultMSISplat
        }
        else {
            Write-ADTLogEntry -Message "No EXE installer and no Zero-Config MSI available to perform installation." -Severity 3
            Show-ADTInstallationPrompt -Message "No installer configured and no Zero-Config MSI available." -ButtonRightText 'OK' -Icon Error -NoWait
            Close-ADTSession -ExitCode 69002
        }
    }


    ##================================================
    ## MARK: Post-Install
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

    ## <Perform Post-Installation tasks here>


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


if ($adtSession.EnableWelcomePrompt) {
    $saiwParams = @{
        AllowDefer     = $true
        DeferTimes     = 3
        CheckDiskSpace = $true
        PersistPrompt  = $true
        CloseProcessesCountdown = 600
    }

    if ($adtSession.AppProcessesToClose -and $adtSession.AppProcessesToClose.Count -gt 0) {
        $saiwParams.CloseProcesses = $adtSession.AppProcessesToClose
    }
    else {
        $saiwParams.CloseProcesses = @($adtSession.InstallName)
    }

    Show-ADTInstallationWelcome @saiwParams
}

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

    # Search for common uninstaller patterns in Program Files (handles unins000.exe, unins001.exe, etc.)
    # This is useful when an app installer creates version-numbered uninstallers (e.g., Git)
    
    if (-not $ExeUninstallerResolved -and -not [string]::IsNullOrWhiteSpace($adtSession.InstallName)) {
        try {
            # Try to find unins*.exe in Program Files (common location for InnoSetup installers)
            $programFilesPath = ${env:ProgramFiles}
            $searchPaths = @($programFilesPath)
            if (${env:ProgramFiles(x86)}) { $searchPaths += ${env:ProgramFiles(x86)} }
            
            foreach ($searchPath in $searchPaths) {
                if (Test-Path -Path $searchPath) {
                    $uninstallers = Get-ChildItem -Path $searchPath -Filter 'unins*.exe' -File -ErrorAction SilentlyContinue
                    if ($uninstallers) {
                        $ExeUninstallerResolved = $uninstallers | Select-Object -ExpandProperty FullName -First 1
                        Write-ADTLogEntry -Message "Found InnoSetup uninstaller: $ExeUninstallerResolved"
                        break
                    }
                }
            }
        }
        catch {
            Write-ADTLogEntry -Message "Error searching for unins*.exe in Program Files: $($_.Exception.Message)" -Severity 2
        }
    }

        # Resolve uninstaller path with this priority:
        # 1) If $ExeUninstallerPath points to an .exe file, use it
        # 2) If $ExeUninstallerPath is a directory and $ExeUninstallerName set, use the combined path
        # 3) If $ExeUninstallerName is set, check $adtSession.DirFiles for the named file
        # 4) Search $adtSession.DirFiles recursively for any EXE with 'uninstall'/'unins'/'uninstaller' in the name
        # 5) Fallback to Zero-Config MSI

    $ExeUninstallerResolved = $null
    $skipUninstaller = $false

    if (-not [string]::IsNullOrWhiteSpace($ExeUninstallerPath)) {
        if ($ExeUninstallerPath -match '(?i)\.exe$' -or (Test-Path -LiteralPath $ExeUninstallerPath -PathType Leaf -ErrorAction SilentlyContinue)) {
            $ExeUninstallerResolved = $ExeUninstallerPath
        }
        elseif (Test-Path -LiteralPath $ExeUninstallerPath -PathType Container -ErrorAction SilentlyContinue) {
            if (-not [string]::IsNullOrWhiteSpace($ExeUninstallerName)) {
                $ExeUninstallerResolved = Join-Path -Path $ExeUninstallerPath -ChildPath $ExeUninstallerName
            }
        }
        else {
            if ($ExeUninstallerPath.TrimEnd('\\/').EndsWith('\\') -or $ExeUninstallerPath.TrimEnd('\\/').EndsWith('/')) {
                if (-not [string]::IsNullOrWhiteSpace($ExeUninstallerName)) {
                    $ExeUninstallerResolved = Join-Path -Path $ExeUninstallerPath -ChildPath $ExeUninstallerName
                }
            }
        }
    }

    if (-not $ExeUninstallerResolved -and -not [string]::IsNullOrWhiteSpace($ExeUninstallerName)) {
        $candidate = Join-Path -Path $adtSession.DirFiles -ChildPath $ExeUninstallerName
        if (Test-Path -LiteralPath $candidate) {
            $ExeUninstallerResolved = $candidate
        }
    }

    if (-not $ExeUninstallerResolved) {
        try {
            $candidates = Get-ChildItem -Path $adtSession.DirFiles -Filter *.exe -Recurse -File -ErrorAction Stop |
                Where-Object { $_.BaseName -match '(?i)unins|uninstall|uninstaller' }
        }
        catch {
            $candidates = Get-ChildItem -Path $adtSession.DirFiles -Filter *.exe -File -ErrorAction SilentlyContinue |
                Where-Object { $_.BaseName -match '(?i)unins|uninstall|uninstaller' }
        }

        if ($candidates -and $candidates.Count -gt 0) {
            $preferred = $candidates |
                Sort-Object -Property @{ Expression = { if ($_.Name -match '(?i)\\buninstall\\b') { 0 } elseif ($_.Name -match '(?i)unins') { 1 } else { 2 } } } |
                Select-Object -First 1
            $ExeUninstallerResolved = $preferred.FullName
            Write-ADTLogEntry -Message "Found uninstaller executable in package files: $ExeUninstallerResolved"
        }
    }

    if ($ExeUninstallerResolved) {
        Write-ADTLogEntry -Message "Starting Uninstallation: $ExeUninstallerResolved with arguments: $ExeUninstallArgs"
        if (-not (Test-Path -LiteralPath $ExeUninstallerResolved)) {
            Write-ADTLogEntry -Message "Uninstaller missing: $ExeUninstallerResolved" -Severity 3

            # Uninstaller missing; prompt the user and exit.
            Show-ADTInstallationPrompt -Message "Uninstaller missing: $ExeUninstallerResolved" -ButtonRightText 'OK' -Icon Error -NoWait
            Close-ADTSession -ExitCode 69003
        }

        if (-not $skipUninstaller) {
            $adtLogDir = 'C:\Windows\Logs\Software'
            if (-not (Test-Path -LiteralPath $adtLogDir)) {
                New-Item -Path $adtLogDir -ItemType Directory -Force | Out-Null
            }

            Start-ADTProcess -FilePath $ExeUninstallerResolved -ArgumentList $ExeUninstallArgs
        }
    }
    else {
        Write-ADTLogEntry -Message "No EXE uninstaller found; falling back to Zero-Config MSI if available." -Severity 2
        if ($adtSession.DefaultMsiFile) {
            $ExecuteDefaultMSISplat = @{ Action = $adtSession.DeploymentType; FilePath = $adtSession.DefaultMsiFile }
            if ($adtSession.DefaultMstFile) {
                $ExecuteDefaultMSISplat.Add('Transforms', $adtSession.DefaultMstFile)
            }
            Start-ADTMsiProcess @ExecuteDefaultMSISplat
        }
        elseif ($adtSession.UseDefaultMsi) {
            $ExecuteDefaultMSISplat = @{ Action = $adtSession.DeploymentType; FilePath = $adtSession.DefaultMsiFile }
            if ($adtSession.DefaultMstFile) {
                $ExecuteDefaultMSISplat.Add('Transforms', $adtSession.DefaultMstFile)
            }
            Start-ADTMsiProcess @ExecuteDefaultMSISplat
        }
        else {
            Write-ADTLogEntry -Message "No EXE uninstaller and no Zero-Config MSI available to perform uninstallation." -Severity 3
            Show-ADTInstallationPrompt -Message "No uninstaller configured and no Zero-Config MSI available." -ButtonRightText 'OK' -Icon Error -NoWait
            Close-ADTSession -ExitCode 69002
        }
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
        $saiwParams = @{
            AllowDefer     = $true
            DeferTimes     = 3
            CheckDiskSpace = $true
            PersistPrompt  = $true
            CloseProcesses = $adtSession.AppProcessesToClose
            CloseProcessesCountdown = 600
        }
        Show-ADTInstallationWelcome @saiwParams
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

