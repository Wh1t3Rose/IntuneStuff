[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
   [int]$StaleDays = 183,
   [int]$DeleteThreshold = 20,
   [switch]$TestMode = $true,
   [string]$ManagedIdentityClientId = '',
   [string]$ResultEmailTo = '',
   [string]$ResultEmailFrom = ''
)

if ($TestMode) { $WhatIfPreference = $true }
if ($TestMode) {
   Write-Output '============================================================'
   Write-Output '===================== TEST MODE ENABLED ===================='
   Write-Output '==== NO DEVICES WILL BE DELETED (WhatIf is in effect) ======'
   Write-Output '============================================================'
} else {
   Write-Output '============================================================'
   Write-Output '===================== LIVE MODE ENABLED ===================='
   Write-Output '==== DEVICES CAN BE DELETED (WhatIf is NOT in effect) ======'
   Write-Output '============================================================'
}
Write-Output "Mode: TestMode=$TestMode; WhatIfPreference=$WhatIfPreference; StaleDays=$StaleDays (~6 months default); DeleteThreshold=$DeleteThreshold"
Write-Output "Runtime: PSEdition=$($PSVersionTable.PSEdition); PSVersion=$($PSVersionTable.PSVersion); Host=$($Host.Name)"

$preloadedModules = Get-Module | Where-Object { $_.Name -like 'Az.*' -or $_.Name -like 'Microsoft.Graph*' } | Sort-Object Name, Version
if ($preloadedModules) {
   Write-Output 'Preloaded Az/Graph modules:'
   $preloadedModules | ForEach-Object { Write-Output " - $($_.Name) $($_.Version)" }
}

$graphToken = $null
$tokenAcquiredBy = $null

$azAccountsAvailable = $false
try {
   Import-Module -Name Az.Accounts -ErrorAction Stop
   $azAccountsAvailable = $true
   Write-Output 'Loaded module: Az.Accounts'
} catch {
   Write-Output "Az.Accounts not loaded: $($_.Exception.Message)"
}

if (
   $azAccountsAvailable -and
   (Get-Command -Name Connect-AzAccount -ErrorAction SilentlyContinue) -and
   (Get-Command -Name Get-AzAccessToken -ErrorAction SilentlyContinue)
) {
   try {
      Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
      if ($ManagedIdentityClientId) {
         Connect-AzAccount -Identity -AccountId $ManagedIdentityClientId -ErrorAction Stop | Out-Null
      } else {
         Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
      }
      $graphToken = (Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -ErrorAction Stop).Token
      if ($graphToken) { $tokenAcquiredBy = 'Az.Accounts' }
   } catch {
      Write-Output "Az.Accounts token path failed: $($_.Exception.Message)"
   }
}

if (-not $graphToken) {
   try {
      if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
         throw 'IDENTITY_ENDPOINT / IDENTITY_HEADER not present in environment.'
      }

      $tokenUri = "$($env:IDENTITY_ENDPOINT)?resource=https://graph.microsoft.com/&api-version=2019-08-01"
      if ($ManagedIdentityClientId) {
         $tokenUri += "&client_id=$([System.Uri]::EscapeDataString($ManagedIdentityClientId))"
      }

      $tokenResponse = Invoke-RestMethod -Method Get -Uri $tokenUri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER; 'Metadata' = 'True' } -ErrorAction Stop
      $graphToken = $tokenResponse.access_token
      if ($graphToken) { $tokenAcquiredBy = 'Automation MSI endpoint' }
   } catch {
      Write-Output "Automation MSI endpoint token path failed: $($_.Exception.Message)"
   }
}

if (-not $graphToken) {
   throw 'Failed to acquire Microsoft Graph token using managed identity. Ensure this runbook has a managed identity enabled and is running in Azure Automation with identity endpoint variables available.'
}

Write-Output "Managed identity token acquired for Microsoft Graph via: $tokenAcquiredBy"

$graphHeaders = @{
   Authorization = "Bearer $graphToken"
   'Content-Type' = 'application/json'
}

function Get-GraphPagedResults {
   param(
      [Parameter(Mandatory = $true)][string]$InitialUri,
      [Parameter(Mandatory = $true)][hashtable]$Headers
   )

   $results = @()
   $nextUri = $InitialUri
   while ($nextUri) {
      $response = Invoke-RestMethod -Method Get -Uri $nextUri -Headers $Headers -ErrorAction Stop
      if ($response.value) {
         $results += $response.value
      }
      $nextUri = $response.'@odata.nextLink'
   }
   return $results
}

# Get Zulu formatted time from stale-days ago for filter
$date = (Get-Date).AddDays(-$StaleDays).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

# Get disabled Windows devices that haven't signed in for more than stale-days
try {
   $filter = "accountEnabled eq false and operatingSystem eq 'Windows' and approximateLastSignInDateTime le $date"
   $select = 'id,displayName,deviceId,operatingSystem,accountEnabled,approximateLastSignInDateTime'
   $devicesUri = "https://graph.microsoft.com/v1.0/devices?`$filter=$([System.Uri]::EscapeDataString($filter))&`$select=$select&`$top=999"
   $devices = @(Get-GraphPagedResults -InitialUri $devicesUri -Headers $graphHeaders)
} catch {
   throw "Failed to query devices from Microsoft Graph. $_"
}

$deviceCount = $devices.Count
Write-Output "Found $deviceCount disabled Windows device(s) inactive for over $StaleDays day(s)."

$deletedDevices = @()
$wouldDeleteDevices = @()
$deletedDeviceRecords = @()
$wouldDeleteDeviceRecords = @()
$runResult = 'Completed'

# If below threshold, delete them (with WhatIf/Confirm support)
if ($deviceCount -lt $DeleteThreshold) {
   $devices | ForEach-Object {
      $displayName = if ($_.displayName) { $_.displayName } else { '<no-displayName>' }
      $deviceId = if ($_.deviceId) { $_.deviceId } else { '<no-deviceId>' }
      $target = "$displayName,$deviceId"
      $deleteUri = "https://graph.microsoft.com/v1.0/devices/$($_.id)"
      Write-Output "Candidate: $target"
      if ($PSCmdlet.ShouldProcess($target, 'DELETE Microsoft Graph device')) {
         Invoke-RestMethod -Method Delete -Uri $deleteUri -Headers $graphHeaders -ErrorAction Stop
         $deletedDevices += $target
         $deletedDeviceRecords += [pscustomobject]@{
            DisplayName = $displayName
            DeviceId = $deviceId
         }
         Write-Output "Deleted: $target"
      } else {
         $wouldDeleteDevices += $target
         $wouldDeleteDeviceRecords += [pscustomobject]@{
            DisplayName = $displayName
            DeviceId = $deviceId
         }
         Write-Output "WouldDelete: $target"
      }
   }

   Write-Output "Deleted count: $($deletedDevices.Count)"
   if ($deletedDevices.Count -gt 0) {
      Write-Output "Deleted devices:"
      $deletedDevices | ForEach-Object { Write-Output " - $_" }
   }

   Write-Output "WouldDelete count: $($wouldDeleteDevices.Count)"
   if ($wouldDeleteDevices.Count -gt 0) {
      Write-Output "WouldDelete devices:"
      $wouldDeleteDevices | ForEach-Object { Write-Output " - $_" }
   }
} else {
   $runResult = 'ThresholdReached'
   Write-Output "Delete threshold reached - $deviceCount devices found"
}

if ($ResultEmailTo) {
   if (-not $ResultEmailFrom) {
      Write-Output 'ResultEmailTo provided but ResultEmailFrom is empty. Skipping email send.'
   } else {
      try {
         $runUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
         $modeText = if ($TestMode) { 'TEST (WhatIf)' } else { 'LIVE' }

         $mailBodyHtml = @"
<html>
<body>
  <h2>Entra Device Cleanup Results</h2>
  <table border='1' cellpadding='6' cellspacing='0' style='border-collapse: collapse;'>
    <tr><th align='left'>RunUtc</th><td>$runUtc</td></tr>
    <tr><th align='left'>Result</th><td>$runResult</td></tr>
    <tr><th align='left'>Mode</th><td>$modeText</td></tr>
    <tr><th align='left'>StaleDays</th><td>$StaleDays</td></tr>
    <tr><th align='left'>DeleteThreshold</th><td>$DeleteThreshold</td></tr>
    <tr><th align='left'>DevicesFound</th><td>$deviceCount</td></tr>
    <tr><th align='left'>DeletedCount</th><td>$($deletedDeviceRecords.Count)</td></tr>
    <tr><th align='left'>WouldDeleteCount</th><td>$($wouldDeleteDeviceRecords.Count)</td></tr>
  </table>
  <p>See attached CSV/TXT files for full Name + DeviceId details.</p>
</body>
</html>
"@

         $detailRows = @()
         $deletedDeviceRecords | ForEach-Object {
            $detailRows += [pscustomobject]@{
               Action = 'Deleted'
               DisplayName = $_.DisplayName
               DeviceId = $_.DeviceId
            }
         }
         $wouldDeleteDeviceRecords | ForEach-Object {
            $detailRows += [pscustomobject]@{
               Action = 'WouldDelete'
               DisplayName = $_.DisplayName
               DeviceId = $_.DeviceId
            }
         }

         $attachments = @()
         if ($detailRows.Count -gt 0) {
            $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
            $csvName = "Entra-DeviceCleanup-Details-$stamp.csv"
            $txtName = "Entra-DeviceCleanup-Details-$stamp.txt"

            $csvContent = ($detailRows | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
            $txtLines = @('Action,DisplayName,DeviceId')
            $detailRows | ForEach-Object { $txtLines += "$($_.Action),$($_.DisplayName),$($_.DeviceId)" }
            $txtContent = $txtLines -join "`r`n"

            $attachments += @{
               '@odata.type' = '#microsoft.graph.fileAttachment'
               name = $csvName
               contentType = 'text/csv'
               contentBytes = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($csvContent))
            }

            $attachments += @{
               '@odata.type' = '#microsoft.graph.fileAttachment'
               name = $txtName
               contentType = 'text/plain'
               contentBytes = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($txtContent))
            }
         }

         $mailPayload = @{
            message = @{
               subject = "Entra Device Cleanup Results ($runResult)"
               body = @{
                  contentType = 'HTML'
                  content = $mailBodyHtml
               }
               toRecipients = @(
                  @{ emailAddress = @{ address = $ResultEmailTo } }
               )
               attachments = $attachments
            }
            saveToSentItems = $true
         }

         $sendMailUri = "https://graph.microsoft.com/v1.0/users/$([System.Uri]::EscapeDataString($ResultEmailFrom))/sendMail"
         Invoke-RestMethod -Method Post -Uri $sendMailUri -Headers $graphHeaders -Body ($mailPayload | ConvertTo-Json -Depth 8) -ErrorAction Stop | Out-Null
         Write-Output "Result email sent to $ResultEmailTo from $ResultEmailFrom"
      } catch {
         Write-Output "Failed to send result email to $ResultEmailTo. $($_.Exception.Message)"
      }
   }
}