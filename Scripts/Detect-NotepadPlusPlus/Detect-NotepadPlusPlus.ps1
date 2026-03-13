$paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$installed = Get-ItemProperty $paths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "Notepad++*" }

if ($installed) {
    Write-Output 1
} else {
    Write-Output 0
}
