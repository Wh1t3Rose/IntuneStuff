# Function to check Chrome in Program Files
function Test-ChromeInProgramFiles {
    $chromePaths = @(
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
    )
    foreach ($path in $chromePaths) {
        if (Test-Path $path) {
            return $true
        }
    }
    return $false
}

# Function to check Chrome in current user's AppData
function Test-ChromeInUserAppData {
    $localAppPath = "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    if (Test-Path $localAppPath) {
        return $true
    }
    return $false
}

# Run detection checks
$foundSystem = Test-ChromeInProgramFiles
$foundUser = Test-ChromeInUserAppData

# Intune detection logic
if ($foundSystem -or $foundUser) {
    Write-Output "Google Chrome is installed."
    exit 0  # Detection success
} else {
    Write-Output "Google Chrome is NOT installed."
    exit 1  # Detection failed
}