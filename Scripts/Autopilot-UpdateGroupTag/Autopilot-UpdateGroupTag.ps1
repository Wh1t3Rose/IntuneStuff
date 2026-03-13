$ClientId    = ''
$ClientSecret = ''
$TenantName    = ''
$grouptag = "Win11-Internal"
$oldGroupTag = "InternalTest"

$ReqTokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    client_Id     = $clientID
    Client_Secret = $clientSecret
} 

$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantName/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody

$Headers = @{
                        "Authorization" = "Bearer $($tokenResponse.access_token)"
                        "ConsistencyLevel" = "Eventual"
                        "Content-type"  = "application/json"
                        }
$apiUrl = 'https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/'

while   ($Null -ne $apiUrl)
        {
        $Data = Invoke-RestMethod -Headers $Headers -Uri $apiUrl -Method Get
        $Devices = ($Data | select-object Value).Value

        $devices = ($data.value | Where-Object groupTag -eq $oldGroupTag)

        $body = '{"groupTag":"'+$groupTag+'"}'

        foreach ($device in $Devices)
                {
                $serial = $device.serialNumber
                $id = $device.id
                $Url = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$id/UpdateDeviceProperties"
                Invoke-RestMethod -Headers $Headers -Uri $Url -Body $body -Method Post -ContentType 'application/json'
                Write-Host "$serial has been added to $grouptag"
                }
        $apiUrl = $Data.'@Odata.nextLink'
        }