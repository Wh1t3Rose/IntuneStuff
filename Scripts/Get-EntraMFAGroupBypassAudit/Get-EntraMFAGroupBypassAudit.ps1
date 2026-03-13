<#
.SYNOPSIS
Reports users that have remained in an Entra Conditional Access MFA Exclusion Group longer than a defined threshold.

.DESCRIPTION
This runbook checks Entra ID audit logs to determine when users were added to a specified MFA exclusion group.
If a user has remained in the group longer than the configured threshold (default 8 hours), the script sends
an email report listing those users.

Designed to run in Azure Automation using a Managed Identity.

.NOTES
Author: Tyler Cox
Version: 1.0
Date: 2026-03-05

CHANGELOG
1.0
- Initial release
- Added Runbook parameters for SendFrom, SendTo, and ExclusionGroupId
- Uses Managed Identity authentication
- Sends HTML formatted email report

REQUIREMENTS
Runtime requirements:
- Az.Accounts module (preferred token path), or
- Azure Automation Managed Identity endpoint variables (IDENTITY_ENDPOINT / IDENTITY_HEADER)

Automation Account Managed Identity Permissions:
AuditLog.Read.All
Group.Read.All
Mail.Send
#>

param(
    [Parameter(Mandatory)]
    [string]$SendFrom,

    [Parameter(Mandatory)]
    [string]$SendTo,

    [string]$ExclusionGroupId = '2c8df932-fca9-4e29-b90d-f02bd6136964',

    [int]$ThresholdMinutes = 240,

    [switch]$WhatIf = $true
)

Write-Output "Starting MFA Exclusion Group Audit"
Write-Output "Threshold Minutes: $ThresholdMinutes"
Write-Output "WhatIf Mode: $WhatIf"

$Now = Get-Date
$ExcludedObjectIds = @(
    'b1e67720-c449-4406-8d0f-b0848a42404c'
)

function Convert-ToPlainTextToken {
    param(
        [Parameter(Mandatory = $true)]
        [object]$TokenValue
    )

    if ($TokenValue -is [string]) {
        return $TokenValue
    }

    if ($TokenValue -is [System.Security.SecureString]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($TokenValue)
        try {
            return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }

    return [string]$TokenValue
}

function Get-GraphToken {
    $token = $null

    try {
        Import-Module -Name Az.Accounts -ErrorAction Stop
        Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        $azToken = Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' -ErrorAction Stop
        if ($azToken.PSObject.Properties.Name -contains 'Token') {
            $token = Convert-ToPlainTextToken -TokenValue $azToken.Token
        }
        elseif ($azToken.PSObject.Properties.Name -contains 'AccessToken') {
            $token = Convert-ToPlainTextToken -TokenValue $azToken.AccessToken
        }
        if ($token) {
            Write-Verbose 'Graph token acquired via Az.Accounts.'
            return $token
        }
    }
    catch {
        Write-Verbose "Az.Accounts token path failed: $($_.Exception.Message)"
    }

    try {
        if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
            throw 'IDENTITY_ENDPOINT / IDENTITY_HEADER not present.'
        }

        $tokenUri = "$($env:IDENTITY_ENDPOINT)?resource=https://graph.microsoft.com/&api-version=2019-08-01"
        $response = Invoke-RestMethod -Method Get -Uri $tokenUri -Headers @{ 'X-IDENTITY-HEADER' = $env:IDENTITY_HEADER; 'Metadata' = 'True' } -ErrorAction Stop
        $token = $response.access_token
        if ($token) {
            Write-Verbose 'Graph token acquired via Automation MSI endpoint.'
            return $token
        }
    }
    catch {
        Write-Verbose "Automation MSI token path failed: $($_.Exception.Message)"
    }

    throw 'Failed to acquire Microsoft Graph token using managed identity.'
}

function Get-GraphPagedResults {
    param(
        [Parameter(Mandatory = $true)][string]$InitialUri,
        [Parameter(Mandatory = $true)][hashtable]$Headers
    )

    $items = @()
    $nextUri = $InitialUri

    while ($nextUri) {
        $response = Invoke-RestMethod -Method Get -Uri $nextUri -Headers $Headers -ErrorAction Stop
        if ($response.value) {
            $items += $response.value
        }
        $nextUri = $response.'@odata.nextLink'
    }

    return $items
}

function Test-AuditEventMatchesMember {
    param(
        [Parameter(Mandatory = $true)]$AuditEvent,
        [Parameter(Mandatory = $true)]$Member,
        [Parameter(Mandatory = $true)][string]$GroupId
    )

    $targetResources = @($AuditEvent.targetResources)
    if (-not $targetResources -or $targetResources.Count -eq 0) {
        return $false
    }

    $hasGroup = $false
    $hasUserById = $false
    $hasUserByUpn = $false
    $hasUserInModifiedProperties = $false

    foreach ($resource in $targetResources) {
        if ($resource.id -eq $GroupId) {
            $hasGroup = $true
        }

        if ($resource.id -eq $Member.Id) {
            $hasUserById = $true
        }

        if ($Member.userPrincipalName -and $resource.userPrincipalName -and $resource.userPrincipalName -eq $Member.userPrincipalName) {
            $hasUserByUpn = $true
        }

        $modifiedProps = @($resource.modifiedProperties)
        foreach ($prop in $modifiedProps) {
            $newValue = [string]$prop.newValue
            $oldValue = [string]$prop.oldValue

            if ($Member.Id -and (($newValue -match [regex]::Escape($Member.Id)) -or ($oldValue -match [regex]::Escape($Member.Id)))) {
                $hasUserInModifiedProperties = $true
            }

            if ($Member.userPrincipalName -and (($newValue -match [regex]::Escape($Member.userPrincipalName)) -or ($oldValue -match [regex]::Escape($Member.userPrincipalName)))) {
                $hasUserInModifiedProperties = $true
            }
        }
    }

    return ($hasGroup -and ($hasUserById -or $hasUserByUpn -or $hasUserInModifiedProperties))
}

Write-Output "Connecting to Microsoft Graph..."
$graphToken = Get-GraphToken

if ([string]::IsNullOrWhiteSpace($graphToken)) {
    throw 'Graph token was empty after acquisition.'
}

$jwtParts = $graphToken.Split('.')
if ($jwtParts.Count -lt 2) {
    throw 'Graph token format is invalid (not a JWT-like token).'
}

$graphHeaders = @{ Authorization = "Bearer $graphToken"; 'Content-Type' = 'application/json' }

# Get user members of exclusion group
Write-Output "Retrieving group members..."
$membersUri = "https://graph.microsoft.com/v1.0/groups/$([System.Uri]::EscapeDataString($ExclusionGroupId))/members/microsoft.graph.user?`$select=id,displayName,userPrincipalName&`$top=999"
$Members = @(Get-GraphPagedResults -InitialUri $membersUri -Headers $graphHeaders)

Write-Output "Retrieving directory audit entries..."
$auditFilter = "(activityDisplayName eq 'Add member to group' or activityDisplayName eq 'Remove member from group') and targetResources/any(t:t/id eq '$ExclusionGroupId')"
$auditUri = "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$filter=$([System.Uri]::EscapeDataString($auditFilter))&`$top=999"
$AuditEntries = @(Get-GraphPagedResults -InitialUri $auditUri -Headers $graphHeaders)

$Report = @()

foreach ($Member in $Members) {

    $UserId = $Member.Id

    if ($ExcludedObjectIds -contains $UserId) {
        Write-Output "Skipping excluded object ID: $UserId"
        continue
    }

    Write-Output "Checking audit logs for user $UserId"

    $MemberEvents = $AuditEntries |
        Where-Object { Test-AuditEventMatchesMember -AuditEvent $_ -Member $Member -GroupId $ExclusionGroupId }

    if (-not $MemberEvents -or $MemberEvents.Count -eq 0) {
        continue
    }

    $LatestAdd = $MemberEvents |
        Where-Object { $_.activityDisplayName -eq 'Add member to group' } |
        Sort-Object ActivityDateTime -Descending |
        Select-Object -First 1

    $LatestRemove = $MemberEvents |
        Where-Object { $_.activityDisplayName -eq 'Remove member from group' } |
        Sort-Object ActivityDateTime -Descending |
        Select-Object -First 1

    if ($null -eq $LatestAdd) {
        continue
    }

    if ($LatestRemove -and ([datetime]$LatestRemove.ActivityDateTime -ge [datetime]$LatestAdd.ActivityDateTime)) {
        continue
    }

    $AddedTime = [datetime]$LatestAdd.ActivityDateTime
    $MinutesInGroup = ($Now - $AddedTime).TotalMinutes

    if ($MinutesInGroup -gt $ThresholdMinutes) {
        $Report += [PSCustomObject]@{
            DisplayName = $Member.displayName
            UserPrincipalName = $Member.userPrincipalName
            AddedToGroup = $AddedTime
            MinutesInGroup = [math]::Round($MinutesInGroup,2)
        }
    }
}

if ($Report.Count -eq 0) {
    Write-Output "No users exceeding threshold."
    return
}

Write-Output "Users exceeding threshold: $($Report.Count)"

# Build HTML Report
$HtmlBody = @"
<h2>MFA Exclusion Group Report</h2>
<p>The following users have remained in the MFA exclusion group longer than $ThresholdMinutes minute(s).</p>
<table border="1" cellpadding="5" cellspacing="0">
<tr>
<th>Name</th>
<th>UPN</th>
<th>Added To Group</th>
<th>Minutes In Group</th>
</tr>
"@

foreach ($Row in $Report) {
    $HtmlBody += "<tr>
<td>$($Row.DisplayName)</td>
<td>$($Row.UserPrincipalName)</td>
<td>$($Row.AddedToGroup)</td>
<td>$($Row.MinutesInGroup)</td>
</tr>"
}

$HtmlBody += "</table>"

if ($WhatIf) {
    Write-Output "WhatIf enabled. Email not sent."
    Write-Output $Report
    return
}

if ([string]::IsNullOrWhiteSpace($SendTo) -or [string]::IsNullOrWhiteSpace($SendFrom)) {
    throw 'SendTo and SendFrom must both be provided to send email.'
}

$SendTo = $SendTo.Trim()
$SendFrom = $SendFrom.Trim()

Write-Output "Sending email report..."
Write-Output "Attempting to send result email to $SendTo from $SendFrom..."

$mailPayload = @{
    message = @{
        subject = 'MFA Exclusion Group Alert'
        body = @{
            contentType = 'HTML'
            content = $HtmlBody
        }
        toRecipients = @(
            @{ emailAddress = @{ address = $SendTo } }
        )
    }
    saveToSentItems = $true
}

try {
    $sendMailUri = "https://graph.microsoft.com/v1.0/users/$([System.Uri]::EscapeDataString($SendFrom))/sendMail"
    Invoke-RestMethod -Method Post -Uri $sendMailUri -Headers $graphHeaders -Body ($mailPayload | ConvertTo-Json -Depth 8) -ErrorAction Stop | Out-Null
    Write-Output "Result email sent to $SendTo from $SendFrom"
}
catch {
    $graphErrorDetails = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { '' }
    Write-Output "Failed to send result email to $SendTo. $($_.Exception.Message)"
    if ($graphErrorDetails) {
        Write-Output "Graph sendMail error details: $graphErrorDetails"
    }
    throw
}

Write-Output "Runbook completed."