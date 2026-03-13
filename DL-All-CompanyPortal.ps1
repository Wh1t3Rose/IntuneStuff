param(
    [string]$CsvPath
)

if (-not $CsvPath) {
    $defaultPath = Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath 'apps.csv'
    $inputPath = Read-Host "Enter CSV path (default: $defaultPath)"
    $CsvPath = if ([string]::IsNullOrWhiteSpace($inputPath)) { $defaultPath } else { $inputPath }
}

$apps = Import-Csv -Path $CsvPath

if (-not $apps) {
    throw "No rows found in CSV: $CsvPath"
}

Add-Type -AssemblyName System.Windows.Forms

foreach ($app in $apps) {
    $appId = $app.'App ID'

    if ([string]::IsNullOrWhiteSpace($appId)) {
        continue
    }

    Start-Process "companyportal:ApplicationId=$appId"
    Start-Sleep -Seconds 10
    [System.Windows.Forms.SendKeys]::SendWait("^{i}")
}
