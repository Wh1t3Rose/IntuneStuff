# Paths to the uninstall tool (x64 and x86)
$toolPaths = @(
    "C:\Program Files\dotnet-core-uninstall\dotnet-core-uninstall.exe",      # x64
    "C:\Program Files (x86)\dotnet-core-uninstall\dotnet-core-uninstall.exe" # x86
)

foreach ($tool in $toolPaths) {
    if (Test-Path $tool) {
        Write-Host "Found uninstall tool at: $tool"

        # Get the list of installed SDKs
        $sdkList = & $tool list | ForEach-Object { $_.Trim() }

        foreach ($line in $sdkList) {
            # Match SDK versions between 5.x and 7.x
            if ($line -match "Microsoft\.NET.*SDK\s+(\d+)\.(\d+)") {
                $major = [int]$matches[1]
                if ($major -ge 5 -and $major -le 7) {
                    Write-Host "Removing .NET SDK version: $($matches[1]).$($matches[2])"
                    & $tool remove --all --sdk "$($matches[1]).$($matches[2])" --force
                }
            }
        }
    }
    else {
        Write-Host "Uninstall tool not found at: $tool"
    }
}

Write-Host "Remediation complete."
