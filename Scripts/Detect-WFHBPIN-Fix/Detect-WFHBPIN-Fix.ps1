$regPath = "HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork\120aeae9-286f-438a-bbf3-de3ab96fcf5d\S-1-12-1-1662966275-1151250520-3510261634-644443005\Policies"
$valueName = "UsePassportForWork"
$expectedValue = 1

try {
    $actualValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop | Select-Object -ExpandProperty $valueName

    if ($actualValue -eq $expectedValue) {
        Write-Output "Detected"
        exit 0
    } else {
        Write-Output "Value found but does not match expected."
        exit 1
    }
}
catch {
    Write-Output "Registry path or value not found."
    exit 1
}
