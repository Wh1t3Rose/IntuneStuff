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

$getAppName = {
    param([object]$Row)
    if ($Row.PSObject.Properties.Name -contains 'Display Name') {
        $val = $Row.'Display Name'
        if (-not [string]::IsNullOrWhiteSpace($val)) { return $val }
    }
    $firstProp = $Row.PSObject.Properties | Select-Object -First 1
    if ($firstProp -and -not [string]::IsNullOrWhiteSpace($firstProp.Value)) { return $firstProp.Value }
    return ''
}

$succeeded = @()
$failed = @()
$skipped = @()

$appIndex = 0
$totalApps = $apps.Count

foreach ($app in $apps) {
    $appIndex++
    $appId = $app.'App ID'

    if ([string]::IsNullOrWhiteSpace($appId)) {
        $skipped += [PSCustomObject]@{
            Index = $appIndex
            AppId = $null
            Name = & $getAppName $app
            Reason = 'Missing App ID'
        }
        continue
    }

    try {
        Start-Process "companyportal:ApplicationId=$appId" -ErrorAction Stop
        Start-Sleep -Seconds 10
        [System.Windows.Forms.SendKeys]::SendWait("^{i}")
        $succeeded += [PSCustomObject]@{
            Index = $appIndex
            AppId = $appId
            Name = & $getAppName $app
        }
    }
    catch {
        $failed += [PSCustomObject]@{
            Index = $appIndex
            AppId = $appId
            Name = & $getAppName $app
            Error = $_.Exception.Message
        }
    }
}

Write-Host "Processed: $totalApps"
Write-Host "Succeeded: $($succeeded.Count)"
Write-Host "Failed: $($failed.Count)"
Write-Host "Skipped: $($skipped.Count)"

if ($succeeded.Count -gt 0) {
    Write-Host "";
    Write-Host "Succeeded items:"
    $succeeded | ForEach-Object { Write-Host ("  [{0}] {1} ({2})" -f $_.Index, $_.Name, $_.AppId) }
}

if ($failed.Count -gt 0) {
    Write-Host "";
    Write-Host "Failed items:"
    $failed | ForEach-Object { Write-Host ("  [{0}] {1} ({2}) - {3}" -f $_.Index, $_.Name, $_.AppId, $_.Error) }
}

if ($skipped.Count -gt 0) {
    Write-Host "";
    Write-Host "Skipped items:"
    $skipped | ForEach-Object { Write-Host ("  [{0}] {1} - {2}" -f $_.Index, $_.Name, $_.Reason) }
}
