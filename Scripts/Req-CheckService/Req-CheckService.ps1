# Requirement script: Check if Qualys Agent is running
$service = Get-Service -Name "QualysAgent" -ErrorAction SilentlyContinue

if ($null -ne $service -and $service.Status -eq 'Running') {
    # Service is running => Requirement NOT met => Return 0
    Write-Output 0
} else {
    # Service is missing or not running => Requirement MET => Return 1
    Write-Output 1
}
