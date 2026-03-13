# Check if .NET 6 runtime is installed
$dotnet = Get-Command "dotnet.exe" -ErrorAction SilentlyContinue
if ($dotnet) {
    $runtimes = & $dotnet.Path --list-runtimes
    if ($runtimes -match "^Microsoft\.NETCore\.App 6\.")
    {
        Write-Output ".NET 6 runtime detected"
        exit 0
    }
}

Write-Output ".NET 6 runtime not found"
exit 1
