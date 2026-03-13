param(
  [string]$DashboardPath = 'C:\Users\TylerCox\Downloads\Material-Design-3-Dynamic-Mobile-Dashboard.yaml',
  [string]$StoragePath = '\\192.168.1.3\appdata\homeassistant\.storage',
  [double]$MinScore = 0.72,
  [double]$MinMargin = 0.08
)

$ErrorActionPreference = 'Stop'

$regPath = Join-Path $StoragePath 'core.entity_registry'
$restorePath = Join-Path $StoragePath 'core.restore_state'
if (-not (Test-Path $DashboardPath)) { throw "Dashboard not found: $DashboardPath" }
if (-not (Test-Path $regPath)) { throw "Missing core.entity_registry at $regPath" }

$valid = @()
$reg = Get-Content -Raw $regPath | ConvertFrom-Json
$valid += @($reg.data.entities | ForEach-Object { $_.entity_id })
if (Test-Path $restorePath) {
  $restore = Get-Content -Raw $restorePath | ConvertFrom-Json
  $valid += @($restore.data | ForEach-Object { $_.state.entity_id })
}
$valid = $valid | Where-Object { $_ } | Sort-Object -Unique
$domains = @($valid | ForEach-Object { ($_ -split '\.')[0] } | Sort-Object -Unique)

$text = Get-Content -Raw $DashboardPath
$tokens = @(([regex]'[a-z_]+\.[a-z0-9_]+').Matches($text) | ForEach-Object Value | Sort-Object -Unique)
$entities = @($tokens | Where-Object { (($_ -split '\.')[0]) -in $domains })
$missingBefore = @($entities | Where-Object { $_ -notin $valid })

function Get-Score {
  param([string]$NameA, [string]$NameB)

  $aParts = @($NameA -split '[^a-z0-9]+' | Where-Object { $_ })
  $bParts = @($NameB -split '[^a-z0-9]+' | Where-Object { $_ })
  if ($aParts.Count -eq 0 -or $bParts.Count -eq 0) { return 0.0 }

  $intersect = @($aParts | Where-Object { $_ -in $bParts }).Count
  $union = @($aParts + $bParts | Sort-Object -Unique).Count
  if ($union -eq 0) { return 0.0 }

  $score = $intersect / $union
  $prefixLen = [Math]::Min(10, $NameA.Length)
  if ($prefixLen -gt 2 -and $NameB.StartsWith($NameA.Substring(0, $prefixLen))) {
    $score += 0.15
  }

  return [Math]::Round($score, 4)
}

$validByDomain = @{}
foreach ($entity in $valid) {
  $domain = ($entity -split '\.')[0]
  if (-not $validByDomain.ContainsKey($domain)) { $validByDomain[$domain] = @() }
  $validByDomain[$domain] += $entity
}

$map = @()
foreach ($missing in $missingBefore) {
  $parts = $missing -split '\.', 2
  if ($parts.Count -lt 2) { continue }

  $domain = $parts[0]
  $name = $parts[1]
  if (-not $validByDomain.ContainsKey($domain)) { continue }

  $best = $null
  $second = $null
  foreach ($candidate in $validByDomain[$domain]) {
    $candidateName = ($candidate -split '\.', 2)[1]
    $score = Get-Score -NameA $name -NameB $candidateName
    $row = [pscustomobject]@{ Missing = $missing; Candidate = $candidate; Score = $score }

    if ($null -eq $best -or $score -gt $best.Score) {
      $second = $best
      $best = $row
    }
    elseif ($null -eq $second -or $score -gt $second.Score) {
      $second = $row
    }
  }

  if ($null -eq $best) { continue }
  $margin = if ($second) { [Math]::Round(($best.Score - $second.Score), 4) } else { $best.Score }

  if ($best.Score -ge $MinScore -and $margin -ge $MinMargin) {
    $map += [pscustomobject]@{
      Missing = $missing
      Candidate = $best.Candidate
      Score = $best.Score
      Margin = $margin
    }
  }
}

$backup = "$DashboardPath.bak.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
Copy-Item -Path $DashboardPath -Destination $backup -Force

foreach ($row in $map) {
  $text = $text.Replace($row.Missing, $row.Candidate)
}
Set-Content -Path $DashboardPath -Value $text -Encoding UTF8

$textAfter = Get-Content -Raw $DashboardPath
$tokensAfter = @(([regex]'[a-z_]+\.[a-z0-9_]+').Matches($textAfter) | ForEach-Object Value | Sort-Object -Unique)
$entitiesAfter = @($tokensAfter | Where-Object { (($_ -split '\.')[0]) -in $domains })
$missingAfter = @($entitiesAfter | Where-Object { $_ -notin $valid })

$mapPath = Join-Path ([System.IO.Path]::GetDirectoryName($DashboardPath)) 'ha-entity-automap.json'
$summaryPath = Join-Path ([System.IO.Path]::GetDirectoryName($DashboardPath)) 'ha-entity-automap-summary.txt'
$map | Sort-Object Score -Descending | ConvertTo-Json -Depth 5 | Set-Content -Path $mapPath -Encoding UTF8

@(
  "Backup: $backup"
  "Missing before: $($missingBefore.Count)"
  "Auto-replaced: $($map.Count)"
  "Missing after: $($missingAfter.Count)"
  "Map file: $mapPath"
  ""
  "Top replacements:"
) + ($map | Sort-Object Score -Descending | Select-Object -First 40 | ForEach-Object {
  "- $($_.Missing) -> $($_.Candidate) (score=$($_.Score), margin=$($_.Margin))"
}) | Set-Content -Path $summaryPath -Encoding UTF8

Get-Content -Path $summaryPath -TotalCount 80
