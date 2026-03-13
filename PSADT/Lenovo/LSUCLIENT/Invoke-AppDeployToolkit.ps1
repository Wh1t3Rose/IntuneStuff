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

# Zero-Config MSI support is provided when "AppName" is null or empty.
# By setting the "AppName" property, Zero-Config MSI will be disabled.
$adtSession = @{
    # App variables.
    AppVendor = 'Lenovo'
    AppName = 'LSUCLIENT'
    AppVersion = ''
    AppArch = ''
    AppLang = 'EN'
    AppRevision = '01'
    AppSuccessExitCodes = @(0)
    AppRebootExitCodes = @(1641, 3010)
    AppProcessesToClose = @('')
    AppScriptVersion = '1.0.0'
    AppScriptDate = '2025-08-23'
    AppScriptAuthor = 'Tyler Cox'
    RequireAdmin = $false

    # Install Titles (Only set here to override defaults set by the toolkit).
    InstallName = 'Lenovo Conmmercial Vantage'
    InstallTitle = 'Lenovo Conmmercial Vantage'

    # Script variables.
    DeployAppScriptFriendlyName = $MyInvocation.MyCommand.Name
    DeployAppScriptParameters = $PSBoundParameters
    DeployAppScriptVersion = '4.1.0'
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

# Welcome prompt with deferral, deadline, disk check, persistent UI, and 10-min auto-continue
$saiwParams = @{
    AllowDefer     = $true
    DeferTimes     = 5
    DeferDeadline  = (Get-Date).AddDays(1)  # set your deadline window here
    ForceCountdown = 600                    # 10 minutes = 600 seconds
    CheckDiskSpace = $true
    PersistPrompt  = $true
}
if ($adtSession.AppProcessesToClose.Count -gt 0) {
    $saiwParams.Add('CloseProcesses', $adtSession.AppProcessesToClose)
}
Show-ADTInstallationWelcome @saiwParams

# Show progress
Show-ADTInstallationProgress



    ## <Perform Pre-Installation tasks here>


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
    # Ensure TLS 1.2 is enforced
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    function Ensure-LSUClientModule {
        [CmdletBinding()]
        param ()

        if (Get-Module -ListAvailable -Name 'LSUClient') {
            return $true
        }

        try {
            if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Force -Confirm:$false
                Import-PackageProvider -Name NuGet -Force
            }

            try {
                Import-Module -Name PowerShellGet -ErrorAction Stop
            }
            catch {
            }

            Install-Module -Name 'LSUClient' -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
            return $true
        }
        catch {
            Write-ADTLogEntry -Message "Install-Module failed for LSUClient; attempting direct PSGallery package fallback. Error: $($_.Exception.Message)" -Severity 2
        }

        $moduleBase = Join-Path -Path ${env:ProgramFiles} -ChildPath 'WindowsPowerShell\Modules'
        if (-not (Test-Path -Path $moduleBase)) {
            New-Item -Path $moduleBase -ItemType Directory -Force | Out-Null
        }

        $tempRoot = Join-Path -Path $env:TEMP -ChildPath ("LSUClient-" + [Guid]::NewGuid().Guid)
        New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null

        try {
            $zipPath = Join-Path -Path $tempRoot -ChildPath 'LSUClient.zip'
            $extractPath = Join-Path -Path $tempRoot -ChildPath 'Extracted'

            Invoke-WebRequest -Uri 'https://www.powershellgallery.com/api/v2/package/LSUClient' -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
            Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

            $manifest = Get-ChildItem -Path $extractPath -Recurse -Filter 'LSUClient.psd1' -ErrorAction Stop | Select-Object -First 1
            if (-not $manifest) {
                throw 'Unable to find LSUClient manifest in downloaded package.'
            }

            $moduleInfo = Import-PowerShellDataFile -Path $manifest.FullName
            $moduleVersion = if ($moduleInfo.ModuleVersion) { $moduleInfo.ModuleVersion.ToString() } else { '0.0.0' }
            $sourcePath = Split-Path -Path $manifest.FullName -Parent
            $targetPath = Join-Path -Path (Join-Path -Path $moduleBase -ChildPath 'LSUClient') -ChildPath $moduleVersion

            New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
            Copy-Item -Path (Join-Path -Path $sourcePath -ChildPath '*') -Destination $targetPath -Recurse -Force
        }
        finally {
            Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
        }

        if (-not (Get-Module -ListAvailable -Name 'LSUClient')) {
            Write-ADTLogEntry -Message 'Failed to install LSUClient module using both Install-Module and PSGallery package fallback. Continuing to create scheduled task; runner script will retry later.' -Severity 2
            return $false
        }

        return $true
    }

    $lsuModuleReady = Ensure-LSUClientModule
    if ($lsuModuleReady) {
        Import-Module -Name 'LSUClient' -Force -ErrorAction Stop

        Write-ADTLogEntry -Message 'Running LSUClient unattended updates during install phase.' -Severity 1
        $updates = Get-LSUpdate | Where-Object { $_.Installer.Unattended }
        if ($updates) {
            $updates | Save-LSUpdate -Verbose
            $updates | Install-LSUpdate -Verbose
        }
        else {
            Write-ADTLogEntry -Message 'No unattended LSU updates available during install phase.' -Severity 1
        }
    }
    else {
        Write-ADTLogEntry -Message 'LSUClient module not ready during install phase; skipping immediate LSU update run.' -Severity 2
    }

    # Create local script used by scheduled task (runs as SYSTEM)
    $lsuTaskScriptRoot = "C:\ProgramData\VACO\Scripts"
    $lsuTaskScriptPath = Join-Path -Path $lsuTaskScriptRoot -ChildPath "Invoke-LSUClientScheduled.ps1"
    if (-not (Test-Path -Path $lsuTaskScriptRoot)) {
        New-Item -Path $lsuTaskScriptRoot -ItemType Directory -Force | Out-Null
    }

    $lsuTaskScriptContent = @'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Ensure-LSUClientModule {
    if (Get-Module -ListAvailable -Name 'LSUClient') {
        return
    }

    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -Force -Confirm:$false
            Import-PackageProvider -Name NuGet -Force
        }

        try {
            Import-Module -Name PowerShellGet -ErrorAction Stop
        }
        catch {
        }

        Install-Module -Name 'LSUClient' -Force -Scope AllUsers -AllowClobber -ErrorAction Stop
        return
    }
    catch {
    }

    $moduleBase = Join-Path -Path ${env:ProgramFiles} -ChildPath 'WindowsPowerShell\Modules'
    if (-not (Test-Path -Path $moduleBase)) {
        New-Item -Path $moduleBase -ItemType Directory -Force | Out-Null
    }

    $tempRoot = Join-Path -Path $env:TEMP -ChildPath ("LSUClient-" + [Guid]::NewGuid().Guid)
    New-Item -Path $tempRoot -ItemType Directory -Force | Out-Null

    try {
        $zipPath = Join-Path -Path $tempRoot -ChildPath 'LSUClient.zip'
        $extractPath = Join-Path -Path $tempRoot -ChildPath 'Extracted'

        Invoke-WebRequest -Uri 'https://www.powershellgallery.com/api/v2/package/LSUClient' -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

        $manifest = Get-ChildItem -Path $extractPath -Recurse -Filter 'LSUClient.psd1' -ErrorAction Stop | Select-Object -First 1
        if (-not $manifest) {
            throw 'Unable to find LSUClient manifest in downloaded package.'
        }

        $moduleInfo = Import-PowerShellDataFile -Path $manifest.FullName
        $moduleVersion = if ($moduleInfo.ModuleVersion) { $moduleInfo.ModuleVersion.ToString() } else { '0.0.0' }
        $sourcePath = Split-Path -Path $manifest.FullName -Parent
        $targetPath = Join-Path -Path (Join-Path -Path $moduleBase -ChildPath 'LSUClient') -ChildPath $moduleVersion

        New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
        Copy-Item -Path (Join-Path -Path $sourcePath -ChildPath '*') -Destination $targetPath -Recurse -Force
    }
    finally {
        Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    if (-not (Get-Module -ListAvailable -Name 'LSUClient')) {
        throw 'Failed to install LSUClient module using both Install-Module and PSGallery package fallback.'
    }
}

Ensure-LSUClientModule

Import-Module -Name 'LSUClient' -Force

$today = Get-Date
$isThirdWednesday = ($today.DayOfWeek -eq [System.DayOfWeek]::Wednesday) -and ($today.Day -ge 15 -and $today.Day -le 21)
if (-not $isThirdWednesday) {
    return
}

$updates = Get-LSUpdate | Where-Object { $_.Installer.Unattended }
if ($updates) {
    $updates | Save-LSUpdate -Verbose
    $updates | Install-LSUpdate -Verbose
}
'@

    Set-Content -Path $lsuTaskScriptPath -Value $lsuTaskScriptContent -Encoding UTF8 -Force

    # Schedule: third Wednesday of every month at 4:00 PM local time
    $lsuTaskName = "VACO-LSUClient-PatchTuesday"
    $lsuTaskDescription = "Runs LSUClient unattended updates at 4:00 PM Wednesdays with in-script enforcement for the third Wednesday of each month."
    $lsuTaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$lsuTaskScriptPath`""
    $lsuTaskTrigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Wednesday -At 4:00PM
    $lsuTaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $lsuTaskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    $lsuTask = New-ScheduledTask -Action $lsuTaskAction -Trigger $lsuTaskTrigger -Principal $lsuTaskPrincipal -Settings $lsuTaskSettings -Description $lsuTaskDescription
    Register-ScheduledTask -TaskName $lsuTaskName -InputObject $lsuTask -Force | Out-Null

    Write-ADTLogEntry -Message "Created/updated scheduled task [$lsuTaskName] to run LSUClient updates as SYSTEM with StartWhenAvailable enabled." -Severity 1


    ##================================================
    ## MARK: Post-Install
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

    ## <Perform Post-Installation tasks here>

    If (-Not (Test-Path -Path "C:\ProgramData\VACO\InstalledApps")) {
        New-Item -ItemType Directory -Path "C:\ProgramData\VACO\InstalledApps" -Force
    }

    New-Item -Path "C:\ProgramData\VACO\InstalledApps\LSUCLIENT.tag" -ItemType File -Force


    ## Display a message at the end of the install.
    if (!$adtSession.UseDefaultMsi)
    {
Show-ADTInstallationPrompt -Message "$($adtSession.InstallTitle) has been installed. You may now open $($adtSession.InstallTitle). Any issues please contact VACO IT." -ButtonRightText 'OK' -Icon Information -NoWait
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
    $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

    ## If there are processes to close, show Welcome Message with a 60 second countdown before automatically closing.
    if ($adtSession.AppProcessesToClose.Count -gt 0)
    {
        Show-ADTInstallationWelcome -CloseProcesses $adtSession.AppProcessesToClose -CloseProcessesCountdown 60
    }

    ## Show Progress Message (with the default message).
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


    ##================================================
    ## MARK: Post-Uninstallation
    ##================================================
    $adtSession.InstallPhase = "Post-$($adtSession.DeploymentType)"

    ## <Perform Post-Uninstallation tasks here>
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
        Import-Module -FullyQualifiedName @{ ModuleName = "$PSScriptRoot\PSAppDeployToolkit\PSAppDeployToolkit.psd1"; Guid = '8c3c366b-8606-4576-9f2d-4051144f7ca2'; ModuleVersion = '4.1.0' } -Force
    }
    else
    {
        Import-Module -FullyQualifiedName @{ ModuleName = 'PSAppDeployToolkit'; Guid = '8c3c366b-8606-4576-9f2d-4051144f7ca2'; ModuleVersion = '4.1.0' } -Force
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

