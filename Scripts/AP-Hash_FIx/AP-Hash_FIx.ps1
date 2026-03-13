<#
.SYNOPSIS
Manages Autopilot hash retrieval remediation scripts for devices with hash-related issues.

.DESCRIPTION
This script automates the management of Autopilot hash retrieval remediation scripts in Intune. It identifies
Autopilot devices that have remediation states other than 'noRemediationRequired' and ensures appropriate
remediation scripts are created for hash retrieval. The script also performs cleanup by removing stale
remediation scripts for devices that no longer require hash remediation.

Key functions:
- Identifies Autopilot devices with hash-related issues
- Creates remediation scripts for devices missing hash retrieval remediation
- Removes outdated remediation scripts for devices that no longer need them

The remediation script naming convention follows: _invCmd_<datetime>_<serialNumber>_getAutopilotHash
#>

$DryRun = $true

function Initialize-GraphConnection {
    try {
        $existingContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($existingContext) {
            Write-Host "Using existing Microsoft Graph context." -ForegroundColor DarkGray
            return
        }

        Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null

        $newContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $newContext) {
            throw "Connect-MgGraph did not establish a context."
        }

        Write-Host "Connected to Microsoft Graph using managed identity." -ForegroundColor Green
    }
    catch {
        throw "Unable to authenticate to Microsoft Graph with managed identity. $($_.Exception.Message)"
    }
}

Initialize-GraphConnection

if ($DryRun) {
    Write-Host "DRY RUN ENABLED: no remediation scripts will be created or removed." -ForegroundColor Yellow
}

function Invoke-GraphBatchRequest {
    param(
        [Parameter(Mandatory = $true)][array]$batchRequest,
        [Parameter(Mandatory = $false)][ValidateSet('v1.0', 'beta')][string]$graphVersion = 'beta'
    )

    $requests = foreach ($request in $batchRequest) {
        @{
            id     = [string]$request.id
            method = [string]$request.method
            url    = [string]$request.url
        }
    }

    $body = @{ requests = $requests } | ConvertTo-Json -Depth 6
    $batchUri = "https://graph.microsoft.com/$graphVersion/`$batch"

    if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
        throw "Authentication needed. Connect-MgGraph did not establish a context before batch request."
    }

    $batchResponse = Invoke-MgGraphRequest -Method POST -Uri $batchUri -Body $body -ContentType "application/json"

    $flattenedResults = [System.Collections.Generic.List[object]]::new()

    foreach ($response in $batchResponse.responses) {
        $responseId = $response.id
        $responseStatus = [int]$response.status

        if ($responseStatus -ge 400) {
            Write-Warning "Batch request '$responseId' failed with status $responseStatus."
            continue
        }

        $responseBody = $response.body
        if ($null -eq $responseBody) {
            continue
        }

        if ($responseBody.PSObject.Properties.Name -contains 'value' -and $responseBody.value) {
            foreach ($item in $responseBody.value) {
                $flattenedResults.Add(($item | Add-Member -NotePropertyName RequestId -NotePropertyValue $responseId -PassThru -Force))
            }
        }
        else {
            $flattenedResults.Add(($responseBody | Add-Member -NotePropertyName RequestId -NotePropertyValue $responseId -PassThru -Force))
        }
    }

    return $flattenedResults
}

$batchRequest = @(
    [PSCustomObject]@{
        id     = "intuneDevices"
        method = "GET"
        URL    = "deviceManagement/managedDevices?`$filter=startswith(operatingSystem,'Windows')"
    },
    [PSCustomObject]@{
        id     = "remediationScripts"
        method = "GET"
        URL    = "deviceManagement/deviceHealthScripts"
    },
    [PSCustomObject]@{
        id     = "autopilotDevices"
        method = "GET"
        URL    = "deviceManagement/windowsAutopilotDeviceIdentities"
    }
)

$allResults = Invoke-GraphBatchRequest -batchRequest $batchRequest -graphVersion beta

$intuneDeviceList = $allResults | ? RequestId -EQ "intuneDevices"
$remediationScriptList = $allResults | ? RequestId -EQ "remediationScripts"
$autopilotDeviceList = $allResults | ? RequestId -EQ "autopilotDevices"

$deviceWithHashIssue = $autopilotDeviceList | ? RemediationState -NE 'noRemediationRequired'
# remediation name format as used in the Get-IntuneDeviceAutopilotHashViaRemediation function
$hashRetrievalRemediation = $remediationScriptList | ? DisplayName -Like '*_getAutopilotHash'

function _extractSerialNumber {
    param ([string[]]$remediationScriptName)

    # name in format _invCmd_<datetime>_<serialNumber>_getAutopilotHash
    $remediationScriptName | % { ($_ -split "_")[-2] }
}

foreach ($device in $deviceWithHashIssue) {
    $serialNumber = $device.serialNumber
    $intuneId = $device.managedDeviceId
    $displayName = $device.displayName

    if ($serialNumber -notin (_extractSerialNumber $hashRetrievalRemediation.DisplayName)) {
        if ($intuneId -notin $intuneDeviceList.id) {
            # try to find the device using serial number
            $intuneId = $intuneDeviceList | ? serialNumber -EQ $serialNumber | sort lastSyncDateTime | select -First 1 -ExpandProperty id

            if (!$intuneId) {
                Write-Warning "Could not find Intune device ID for device '$displayName' ($serialNumber). Skipping remediation creation."
                continue
            }
        }

        Write-Host "Creating remediation script for device '$displayName' ($serialNumber)"
        if ($DryRun) {
            Write-Host "[DRY RUN] Would create remediation for Intune device ID '$intuneId'." -ForegroundColor Cyan
        }
        else {
            Get-IntuneDeviceAutopilotHashViaRemediation -id $intuneId -dontWait
        }
    } else {
        Write-Host "Remediation script already exists for device '$displayName' ($serialNumber). Skipping creation"
    }
}

# stale remediation scripts cleanup
$hashRetrievalRemediation | % {
    # name in format _invCmd_<datetime>_<serialNumber>_getAutopilotHash
    $serialNumber = _extractSerialNumber $_.DisplayName

    if ($serialNumber -notin $deviceWithHashIssue.serialNumber) {
        Write-Host "Removing stale remediation script for device with serial number $serialNumber ($($_.displayName))"
        if ($DryRun) {
            Write-Host "[DRY RUN] Would remove remediation script ID '$($_.id)'." -ForegroundColor Cyan
        }
        else {
            Remove-IntuneRemediation -remediationScriptId $_.id
        }
    }
}