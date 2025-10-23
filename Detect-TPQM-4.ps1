# Detect presence of the TPQM Assistant folder
$exePath = "C:\Program Files (x86)\Lenovo\TPQM\Assistant\TPQMAssistant.exe"
if (Test-Path -Path $exePath) {
    Write-Output "TPQMAssistant.exe present at: $exePath"
    exit 1
} else {
    Write-Output "TPQMAssistant.exe not present"
    exit 0
}