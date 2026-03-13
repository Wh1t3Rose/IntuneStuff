<# 
DETECTION SCRIPT
Looks for Intune MDM enrollment entries where the UPN domain does not match $expectedDomain.
Exit 0 = compliant
Exit 1 = mismatch found
#>

[CmdletBinding()]
param()

$expectedDomain = 'highspring.com'   # change if needed
$baseKey        = 'HKLM:\SOFTWARE\Microsoft\Enrollments'

$mismatches = @()

Get-ChildItem -Path $baseKey -ErrorAction SilentlyContinue | ForEach-Object {
    $keyPath = $_.PsPath
    $props   = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue

    if ($props.ProviderID -ne 'MS DM Server') {
        return
    }

    $upn = $props.UPN

    if ([string]::IsNullOrWhiteSpace($upn)) {
        return
    }

    if ($upn -notlike '*@*') {
        return
    }

    $user, $domain = $upn.Split('@', 2)

    if ($domain -and ($domain -ne $expectedDomain)) {
        $mismatches += [pscustomobject]@{
            EnrollmentId = $_.PSChildName
            KeyPath      = $keyPath
            CurrentUPN   = $upn
            ExpectedUPN  = "$user@$expectedDomain"
        }
    }
}

if ($mismatches.Count -gt 0) {
    Write-Output "Found UPN mismatches under $baseKey"
    $mismatches | Format-Table -AutoSize | Out-String | Write-Output
    exit 1
}
else {
    Write-Output "No UPN mismatches found under $baseKey"
    exit 0
}