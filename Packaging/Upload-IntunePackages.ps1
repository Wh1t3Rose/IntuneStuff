<#
.SYNOPSIS
		Upload .intunewin files to Intune using IntuneWin32App/Graph helper cmdlets.

.DESCRIPTION
		Scans the provided upload folder for .intunewin packages and uploads each
		package to Microsoft Intune. For each package the script attempts to:
			- Build typed detection rules (MSI/File/Script/TagFile) and requirement
				rules using `IntuneWin32App` helper cmdlets when available.
			- Create an icon object from common image files found next to the package.
			- Write a sidecar `<basename>.detection.json` containing discovered detection
				metadata.
			- Present per-package prompts for uninstall mode and assignment groups when
				not running in `-DryRun` mode.
		The script supports a `-DryRun` mode (no uploads, no module installs, no
		authentication) and emits detailed logs to `Upload-IntunePackages.log`.

.NOTES
		Authentication
			- Prefers `Connect-MSIntuneGraph` (if available) and supports interactive
				auth (auth-code + PKCE), device-code (`-DeviceCode`), and client-secret
				flows. If `Connect-MSIntuneGraph` is not available the script falls back
				to `Connect-MgGraph` with equivalent flows.
			- When running with `-DryRun` the script will not attempt authentication.

		Behavior
			- The script attempts to build typed detection and requirement objects and
				will only pass those helper objects to `Add-IntuneWin32App` if they are
				in the expected types (OrderedDictionary or arrays of OrderedDictionary).
			- Per-package metadata (Notes, Owner, Description) and prompts are used
				to improve uploaded app records. Sidecar detection JSON is written near
				each `.intunewin` file.

		Logging & Security
			- Activity and errors are appended to `Upload-IntunePackages.log` in the
				script folder.
			- Do not hard-code sensitive credentials (ClientSecret) into this file in
				production. If a secret was accidentally committed, rotate it
				immediately.

		Usage
			- Typical invocation: `.\Upload-IntunePackages.ps1 -UploadFolder .\!Packages\!upload -DryRun`
			- To perform unattended auth with a client secret supply `-ClientSecret`
				(discouraged in shared/source-controlled scripts).
#>

param(
	[string]$UploadFolder = $(Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath '!Packages\!upload'),
	[string]$AppLogosFolder = $(Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath '!Packages\!upload\AppLogos'),
	[string]$Publisher = '',
	[string]$ModulePath = '',
	[string]$TenantID = '',
	[string]$ClientID = '',
	[string]$ClientSecret = '',
	[switch]$DeviceCode,
	[string[]]$Scopes = @('DeviceManagementApps.ReadWrite.All','offline_access'),
	[switch]$DryRun,
	[switch]$Force
)

$LogFile = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath 'Upload-IntunePackages.log'
"`n--- Run at $(Get-Date) ---`n" | Out-File -FilePath $LogFile -Encoding utf8 -Append
function Write-Log { param($m,$lvl='INFO') $t=(Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); $l="[$t] [$lvl] $m"; Write-Output $l; Add-Content -Path $LogFile -Value $l }

function Clean-DisplayName { 
	param([string]$Name)
	if (-not $Name) { return $Name }

	$s = $Name -replace '[\[\]\(\)]',''
	$s = [regex]::Replace($s, '[-_.]', ' ')

	# Remove common version tokens like v1.2.3 and stray short numbers
	$s = [regex]::Replace($s, '(?i)\bv?\d+([._]\d+)+\b', '')
	$s = [regex]::Replace($s, '(?i)\b\d{1,4}\b', '')

	# Blacklist noisy tokens that should not appear in Intune display names
	$blacklist = @('setup','setupfile','installer','install','msi','exe','zip','portable','full','release','beta','rc','build','silent','64bit','64-bit','x64','x86','amd64','win64','win32')
	foreach ($w in $blacklist) { $s = [regex]::Replace($s, "(?i)\b" + [regex]::Escape($w) + "\b", '') }

	# Normalize whitespace and title-case
	$s = $s -replace '\s+',' '
	$s = $s.Trim()
	if (-not $s) { $s = $Name }
	try { $s = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ToTitleCase($s.ToLower()) } catch { }
	return $s
}

# Find a matching logo image in AppLogos folder (case-insensitive, partial match)
function Find-AppLogo {
	param([string]$AppName, [string]$LogosFolder)
	if (-not $AppName -or -not $LogosFolder -or -not (Test-Path -Path $LogosFolder)) { return $null }
	$logoPatterns = @('*.png', '*.jpg', '*.jpeg', '*.ico', '*.bmp')
	try {
		# Try exact or near-exact match first
		foreach ($pattern in $logoPatterns) {
			$candidates = Get-ChildItem -Path $LogosFolder -Filter $pattern -File -ErrorAction SilentlyContinue
			foreach ($candidate in $candidates) {
				$baseName = [System.IO.Path]::GetFileNameWithoutExtension($candidate.Name)
				# Exact match (case-insensitive)
				if ($baseName -ieq $AppName) { return $candidate.FullName }
				# Check if AppName is contained in the filename
				if ($candidate.Name -ilike "*$AppName*") { return $candidate.FullName }
			}
		}
		# If no exact match, try matching the first word(s) of AppName
		$firstWord = ($AppName -split ' ')[0]
		if ($firstWord -and $firstWord.Length -gt 2) {
			foreach ($pattern in $logoPatterns) {
				$candidates = Get-ChildItem -Path $LogosFolder -Filter $pattern -File -ErrorAction SilentlyContinue
				foreach ($candidate in $candidates) {
					if ($candidate.Name -ilike "*$firstWord*") { return $candidate.FullName }
				}
			}
		}
	} catch {}
	return $null
}

# Try to extract a preferred app display name from a PSADT Invoke-AppDeployToolkit.ps1
function Get-PSADTDisplayNameFromScript {
	param([string]$Directory)
	if (-not $Directory) { return $null }
	$file = Join-Path -Path $Directory -ChildPath 'Invoke-AppDeployToolkit.ps1'
	if (-not (Test-Path -Path $file)) { return $null }
	try {
		$text = Get-Content -Path $file -Raw -ErrorAction SilentlyContinue
		if ($text) {
			$lines = $text -split "\r?\n"
			foreach ($line in $lines) {
				$l = $line.Trim()
				if ($l -match '^\$AppName\s*=') {
					$val = $l -replace '^\$AppName\s*=\s*', ''
					$val = $val.Trim()
					$val = $val.Trim('"', "'")
					if ($val) { return $val }
				}
			}
			foreach ($line in $lines) {
				$l = $line.Trim()
				if ($l -match '^\$InstallName\s*=') {
					$val = $l -replace '^\$InstallName\s*=\s*', ''
					$val = $val.Trim()
					$val = $val.Trim('"', "'")
					if ($val) { return $val }
				}
			}
			foreach ($line in $lines) {
				$l = $line.Trim()
				if ($l -match '^\$InstallTitle\s*=') {
					$val = $l -replace '^\$InstallTitle\s*=\s*', ''
					$val = $val.Trim()
					$val = $val.Trim('"', "'")
					if ($val) { return $val }
				}
			}
		}
	} catch {}
	return $null
}

if (-not (Test-Path -Path $UploadFolder)) { Write-Log "Upload folder not found: $UploadFolder" 'ERROR'; throw "Upload folder not found: $UploadFolder" }

# Ensure helper module
$moduleName = 'IntuneWin32App'
if ($ModulePath -and (Test-Path $ModulePath)) { Import-Module -Name $ModulePath -ErrorAction Stop; Write-Log "Imported module from $ModulePath" }
elseif (-not (Get-Module -ListAvailable -Name $moduleName)) {
	if (-not $DryRun) { Write-Log "Installing $moduleName from PSGallery" 'INFO'; Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop } else { Write-Log "Dry-run: would install $moduleName from PSGallery" 'INFO' }
} else { Write-Log "$moduleName present" 'INFO' }

# Ask for Tenant/Client/Secret only when running (not DryRun)
if (-not $DryRun) {
	if (-not $TenantID) { $TenantID = Read-Host 'Enter Tenant ID (e.g. name.onmicrosoft.com) or press Enter to use account default' }
	if (-not $ClientID) { $ClientID = Read-Host 'Enter Client ID (Application ID) from your Entra app registration' }
	if (-not $ClientSecret) { $cs = Read-Host 'Enter Client Secret for unattended auth (leave empty for interactive/device code)'; if ($cs) { $ClientSecret = $cs } }
}

# Authenticate
if (-not $DryRun) {
	if (Get-Command -Name Connect-MSIntuneGraph -ErrorAction SilentlyContinue) {
		Write-Log 'Using Connect-MSIntuneGraph for authentication' 'INFO'
		try {
			if ($DeviceCode) {
				Write-Log 'Authenticating via device code (Connect-MSIntuneGraph -DeviceCode)' 'INFO'
				Connect-MSIntuneGraph -DeviceCode -ErrorAction Stop
			} elseif ($ClientSecret) {
				Write-Log 'Authenticating using client secret (Connect-MSIntuneGraph -ClientId/ -TenantId/ -ClientSecret)' 'INFO'
				Connect-MSIntuneGraph -ClientId $ClientID -TenantId $TenantID -ClientSecret $ClientSecret -ErrorAction Stop
			} else {
				Write-Log 'Authenticating interactively via Connect-MSIntuneGraph' 'INFO'
				Connect-MSIntuneGraph -Scopes $Scopes -ErrorAction Stop
			}
			Write-Log 'Authenticated with Connect-MSIntuneGraph' 'INFO'
		} catch {
			Write-Log "Connect-MSIntuneGraph authentication failed: $($_.Exception.Message)" 'WARN'
		}
	} else {
		Write-Log 'Connect-MSIntuneGraph not available, falling back to Connect-MgGraph' 'INFO'
		try {
			if ($DeviceCode) {
				Write-Log 'Authenticating via device code (Connect-MgGraph -DeviceCode)' 'INFO'
				Connect-MgGraph -DeviceCode -Scopes $Scopes -ErrorAction Stop
			} elseif ($ClientSecret) {
				Write-Log 'Authenticating using client secret (Connect-MgGraph -ClientId/ -TenantId/ -ClientSecret)' 'INFO'
				Connect-MgGraph -ClientId $ClientID -TenantId $TenantID -ClientSecret $ClientSecret -Scopes $Scopes -ErrorAction Stop
			} else {
				Write-Log 'Authenticating interactively via Connect-MgGraph' 'INFO'
				Connect-MgGraph -Scopes $Scopes -ErrorAction Stop
			}
			Write-Log 'Authenticated with Connect-MgGraph' 'INFO'
		} catch {
			Write-Log "Connect-MgGraph authentication failed: $($_.Exception.Message)" 'ERROR'
			throw "Authentication failed: $($_.Exception.Message)"
		}
	}
}

# Defaults for PSAppDeployToolkit packages
$DefaultInstallCmd = '.\Invoke-AppDeployToolkit.exe -DeploymentType Install -DeployMode Silent'
$DefaultUninstallCmd = '.\Invoke-AppDeployToolkit.exe -DeploymentType Uninstall -DeployMode Silent'

# Find .intunewin files
$pkgs = Get-ChildItem -Path $UploadFolder -Filter *.intunewin -File -ErrorAction SilentlyContinue
if (-not $pkgs -or $pkgs.Count -eq 0) { Write-Log "No .intunewin files found in $UploadFolder" 'WARN'; exit 0 }

$plannedUploads = @()
foreach ($p in $pkgs) {
	$rawName = [System.IO.Path]::GetFileNameWithoutExtension($p.Name)
	$displayName = Clean-DisplayName -Name $rawName
	$detectionRule = $null
	$requirementRule = $null
	$iconObj = $null
	$logoPath = $null
	$returnCodes = @()
	$requiredGroups = @()
	$availableGroups = @()
	# Per-package answers file path
	$answerFile = Join-Path $p.DirectoryName ($p.BaseName + '.answers.json')
	$useAnswers = $false

	# If the package folder contains a PSADT Invoke-AppDeployToolkit.ps1, prefer its AppName/InstallName/InstallTitle
	try {
		$psadtName = Get-PSADTDisplayNameFromScript -Directory $p.DirectoryName
		if ($psadtName) { $displayName = Clean-DisplayName -Name $psadtName; Write-Log "Using PSADT name from Invoke-AppDeployToolkit.ps1: $psadtName" 'INFO' }
	} catch {}

	# If an answers file exists, offer to reuse saved answers
	if (-not $DryRun -and (Test-Path $answerFile)) {
		try {
			Write-Host "Found answers file for '$displayName' at $answerFile. Use saved answers? (Y/n) " -ForegroundColor Cyan -NoNewline
			$useResp = Read-Host
			if (-not $useResp -or $useResp.Trim() -match '^[Yy]') {
				try {
					$ans = Get-Content $answerFile -Raw | ConvertFrom-Json -ErrorAction Stop
					if ($ans.UninstallCmd) { $uninstallCmd = $ans.UninstallCmd }
					if ($ans.LogoPath) { $logoPath = $ans.LogoPath }
					if ($ans.RequiredGroups) { $requiredGroups = @($ans.RequiredGroups) }
					if ($ans.AvailableGroups) { $availableGroups = @($ans.AvailableGroups) }
					if ($ans.ReturnCodes) {
						$returnCodes = @()
						if (Get-Command -Name New-IntuneWin32AppReturnCode -ErrorAction SilentlyContinue) {
							foreach ($rcs in $ans.ReturnCodes) {
								if ($rcs -match '^(\d+):(.+)$') {
									try { $returnCodes += New-IntuneWin32AppReturnCode -ReturnCode ([int]$Matches[1]) -Type $Matches[2] } catch { }
								}
							}
						}
					}
					Write-Log "Loaded answers from $answerFile for $displayName" 'INFO'
					$useAnswers = $true
				} catch {
					Write-Log "Failed to load answers file ${answerFile}: $($_.Exception.Message)" 'WARN'
				}
			}
		} catch { }
	}

	$notes = "Uploaded from packaging pipeline: $($p.Name)"

	# Description
	$description = $null
	$descCandidates = @([System.IO.Path]::Combine($p.DirectoryName, "$rawName.txt"), [System.IO.Path]::Combine($p.DirectoryName, 'description.txt'), [System.IO.Path]::Combine($p.DirectoryName,'README.md'))
	foreach ($df in $descCandidates) { if (Test-Path $df) { $lines = Get-Content $df -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne '' }; if ($lines) { $description = ($lines | Select-Object -First 2) -join ' '; break } } }
	if (-not $description) { $description = "Installs $displayName using PSAppDeployToolkit." }

	Write-Log "Preparing to upload $($p.FullName) as '$displayName'"

	# Detection discovery
	$detection = @{ Type='Unknown'; Value=$null; Version=$null }
	try {
		if (Get-Command -Name Get-IntuneWin32AppMetaData -ErrorAction SilentlyContinue) {
			$meta = Get-IntuneWin32AppMetaData -FilePath $p.FullName -ErrorAction SilentlyContinue
			if ($meta -and $meta.ApplicationInfo -and $meta.ApplicationInfo.MsiInfo -and $meta.ApplicationInfo.MsiInfo.MsiProductCode) {
				$detection.Type = 'MSI'
				$detection.Value = $meta.ApplicationInfo.MsiInfo.MsiProductCode
			}
		}
	} catch {}
	if ($detection.Type -eq 'Unknown') {
		$pf = @(); if ($env:ProgramFiles) { $pf += $env:ProgramFiles }; if (${env:ProgramFiles(x86)}) { $pf += ${env:ProgramFiles(x86)} }
		foreach ($root in $pf) { try { $m = Get-ChildItem -Path $root -Filter '*.exe' -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.BaseName -ilike "*$rawName*" } | Select-Object -First 1; if ($m) { $detection.Type='File'; $detection.Value=$m.FullName; break } } catch {} }
	}
	if ($detection.Type -eq 'Unknown') { $tagFolder='C:\ProgramData\VACO\InstalledApps'; if (Test-Path $tagFolder) { $t=Get-ChildItem -Path $tagFolder -Filter "*$rawName*.tag" -File -ErrorAction SilentlyContinue | Select-Object -First 1; if ($t) { $detection.Type='TagFile'; $detection.Value=$t.FullName; $detection.Version=(Get-Content $t -ErrorAction SilentlyContinue | Select-Object -First 1) } } }

	if ($detection.Type -eq 'Unknown') { $resp = Read-Host "Detection not found for $displayName. Enter 'File=C:\path\app.exe' or 'TagFile=C:\path\file.tag', or press Enter to skip"; if ($resp -and $resp -match '^(File|TagFile)=(.+)$') { $detection.Type=$matches[1]; $detection.Value=$matches[2].Trim('"', "'") } }

	# If user didn't provide detection via standard prefix, allow flexible inputs and try to build typed rules
	if ($detection.Type -eq 'Unknown') {
		$resp = Read-Host "Detection not found for $displayName. Enter one of: `n  File=C:\path\app.exe`n  MSI={GUID}[;Version=1.2.3][;Operator=greaterThanOrEqual]`n  TagFile=C:\path\file.tag`nOr press Enter to skip"
		if ($resp -and $resp.Trim() -ne '') {
			$resp = $resp.Trim()
			# File=...
			if ($resp -match '^File=(.+)$') {
				$detection.Type = 'File'
				$detection.Value = $matches[1].Trim().Trim('"', "'")
				if (Get-Command -Name New-IntuneWin32AppDetectionRuleFile -ErrorAction SilentlyContinue) {
					try {
						$fp = [System.IO.Path]::GetDirectoryName($detection.Value)
						$fn = [System.IO.Path]::GetFileName($detection.Value)
						$detectionRule = New-IntuneWin32AppDetectionRuleFile -Existence -FileOrFolder $fn -Path $fp -Check32BitOn64System $false -DetectionType 'exists'
						Write-Log "Built File DetectionRule for $($detection.Value)" 'INFO'
					} catch { Write-Log "Failed to build File detection rule from input: $($_.Exception.Message)" 'WARN' }
				}
			}
			# MSI=GUID[;...]
			elseif ($resp -match '^MSI=\{?([0-9A-Fa-f\-]{36})\}?(?:;(.*))?$') {
				$guid = $matches[1]
				$params = @{}
				if ($matches[2]) {
					$rest = $matches[2] -split ';' | ForEach-Object { $_.Trim() }
					foreach ($kv in $rest) {
						if ($kv -match '^(Version)=(.+)$') { $params['ProductVersion'] = $Matches[2].Trim() }
						elseif ($kv -match '^(Operator|ProductVersionOperator)=(.+)$') { $params['ProductVersionOperator'] = $Matches[2].Trim() }
					}
				}
				$detection.Type = 'MSI'
				$detection.Value = $guid
				if (Get-Command -Name New-IntuneWin32AppDetectionRuleMSI -ErrorAction SilentlyContinue) {
					try {
						$msiArgs = @{ ProductCode = $guid }
						if ($params['ProductVersionOperator']) { $msiArgs['ProductVersionOperator'] = $params['ProductVersionOperator'] }
						if ($params['ProductVersion']) { $msiArgs['ProductVersion'] = $params['ProductVersion'] }
						$detectionRule = New-IntuneWin32AppDetectionRuleMSI @msiArgs
						Write-Log "Built MSI DetectionRule using product code $guid" 'INFO'
					} catch { Write-Log "Failed to build MSI detection rule: $($_.Exception.Message)" 'WARN' }
				}
			}
			# TagFile=...
			elseif ($resp -match '^TagFile=(.+)$') {
				$detection.Type = 'TagFile'
				$detection.Value = $matches[1].Trim().Trim('"', "'")
				# If tag file contains MSI info, try to extract
				try {
					if (Test-Path $detection.Value) {
						$content = Get-Content -Path $detection.Value -ErrorAction SilentlyContinue | Out-String
						if ($content -match '({[0-9A-Fa-f\-]{36}})') {
							$foundGuid = $Matches[1].Trim('{','}')
							if (Get-Command -Name New-IntuneWin32AppDetectionRuleMSI -ErrorAction SilentlyContinue) {
								try { $detectionRule = New-IntuneWin32AppDetectionRuleMSI -ProductCode $foundGuid; Write-Log "Built MSI DetectionRule from tag file product code $foundGuid" 'INFO' } catch { }
							}
						}
					}
				} catch {}
			}
			# Plain path or GUID
			else {
				$respTrimmed = $resp.Trim().Trim('"', "'")
				if (Test-Path $respTrimmed) {
					$ext = [System.IO.Path]::GetExtension($respTrimmed).ToLower()
					if ($ext -eq '.exe') { $detection.Type='File'; $detection.Value=$respTrimmed; if (Get-Command -Name New-IntuneWin32AppDetectionRuleFile -ErrorAction SilentlyContinue) { try { $fn=[System.IO.Path]::GetFileName($respTrimmed); $fp=[System.IO.Path]::GetDirectoryName($respTrimmed); $detectionRule = New-IntuneWin32AppDetectionRuleFile -Existence -FileOrFolder $fn -Path $fp -Check32BitOn64System $false -DetectionType 'exists'; Write-Log "Built File DetectionRule for $respTrimmed" 'INFO' } catch { } } }
					elseif ($ext -eq '.tag') { $detection.Type='TagFile'; $detection.Value=$respTrimmed }
					else { $detection.Type='Custom'; $detection.Value=$respTrimmed }
				} elseif ($respTrimmed -match '^{?[0-9A-Fa-f\-]{36}}?$') {
					# looks like a GUID -> treat as MSI product code
					$guid = $respTrimmed.Trim('{','}')
					$detection.Type='MSI'; $detection.Value=$guid
					if (Get-Command -Name New-IntuneWin32AppDetectionRuleMSI -ErrorAction SilentlyContinue) {
						try { $detectionRule = New-IntuneWin32AppDetectionRuleMSI -ProductCode $guid; Write-Log "Built MSI DetectionRule using product code $guid" 'INFO' } catch { }
					}
				} else {
					$detection.Type='Custom'; $detection.Value=$resp
				}
			}
		}
	}

	$notes += "`nDetection: $($detection.Type) -> $($detection.Value)"

	# Build helper objects (respect any detectionRule created earlier from user input)
	if (-not $detectionRule) {
		if ($detection.Type -eq 'MSI' -and (Get-Command -Name New-IntuneWin32AppDetectionRuleMSI -ErrorAction SilentlyContinue)) {
			try { $detectionRule = New-IntuneWin32AppDetectionRuleMSI -ProductCode $detection.Value; Write-Log "Built MSI DetectionRule" 'INFO' } catch { Write-Log "MSI detection rule failed: $($_.Exception.Message)" 'WARN' }
		}
		elseif ($detection.Type -eq 'File' -and (Get-Command -Name New-IntuneWin32AppDetectionRuleFile -ErrorAction SilentlyContinue)) {
			try { $fn=[System.IO.Path]::GetFileName($detection.Value); $fp=[System.IO.Path]::GetDirectoryName($detection.Value); $detectionRule = New-IntuneWin32AppDetectionRuleFile -Existence -FileOrFolder $fn -Path $fp -Check32BitOn64System $false -DetectionType 'exists'; Write-Log "Built File DetectionRule" 'INFO' } catch { Write-Log "File detection rule failed: $($_.Exception.Message)" 'WARN' }
		}
	}

	# Script detection: if a detection script exists in the package folder, prefer creating a script detection rule
	try {
		$scriptDetectionFile = Get-ChildItem -Path $p.DirectoryName -Filter '*detection*.ps1' -File -ErrorAction SilentlyContinue | Select-Object -First 1
		if ($scriptDetectionFile -and -not $detectionRule -and (Get-Command -Name New-IntuneWin32AppDetectionRuleScript -ErrorAction SilentlyContinue)) {
			try { $detectionRule = New-IntuneWin32AppDetectionRuleScript -ScriptFile $scriptDetectionFile.FullName -EnforceSignatureCheck $false -RunAs32Bit $false; Write-Log "Built Script DetectionRule from $($scriptDetectionFile.Name)" 'INFO' } catch { Write-Log "Script detection rule failed: $($_.Exception.Message)" 'WARN' }
		}
	} catch {}

	# Build requirement rule: try using MinimumSupportedWindowsRelease then fallback to MinimumSupportedOperatingSystem token mapping
	function Convert-MinWindowsReleaseToken { param([string]$r) switch ($r) { '1607' { 'W10_1607' } '1703' { 'W10_1703' } '1709' { 'W10_1709' } '1803' { 'W10_1803' } '1809' { 'W10_1809' } '1903' { 'W10_1903' } '1909' { 'W10_1909' } '2004' { 'W10_2004' } '20H2' { 'W10_20H2' } '21H1' { 'W10_21H1' } '21H2' { 'W10_21H2' } '22H2' { 'W10_22H2' } '21H2-W11' { 'W11_21H2' } '22H2-W11' { 'W11_22H2' } default { $null } } }
	if (Get-Command -Name New-IntuneWin32AppRequirementRule -ErrorAction SilentlyContinue) {
		try {
			$archVal = 'x64'
			$minWinRelease = '20H2'
			if (-not $requirementRule) {
				try {
					$requirementRule = New-IntuneWin32AppRequirementRule -Architecture $archVal -MinimumSupportedWindowsRelease $minWinRelease
					Write-Log "Built RequirementRule (Architecture: $archVal, MinWindowsRelease: $minWinRelease)" 'INFO'
				} catch {
					$mapped = Convert-MinWindowsReleaseToken -r $minWinRelease
					if ($mapped) {
						try { $requirementRule = New-IntuneWin32AppRequirementRule -Architecture $archVal -MinimumSupportedOperatingSystem $mapped; Write-Log "Built RequirementRule (Architecture: $archVal, MinOSToken: $mapped)" 'INFO' } catch { Write-Log "Failed to build RequirementRule with mapped token: $($_.Exception.Message)" 'WARN' }
					} else { Write-Log 'Unable to map minimum Windows release token for RequirementRule' 'WARN' }
				}
			}
		} catch { Write-Log "RequirementRule creation failed: $($_.Exception.Message)" 'WARN' }
	}

	# Per-package logo/icon prompt and search (BEFORE icon creation)
	try {
		if ($useAnswers) {
			if ($logoPath) { Write-Log "Using saved logo for '$displayName': $logoPath" 'INFO' }
		} elseif (-not $DryRun) {
			# First, try to find a matching logo in AppLogos folder
			$foundLogo = Find-AppLogo -AppName $displayName -LogosFolder $AppLogosFolder
			if (-not $foundLogo) {
				$foundLogo = Find-AppLogo -AppName $rawName -LogosFolder $AppLogosFolder
			}
			
			if ($foundLogo) {
				Write-Log "Found matching logo in AppLogos: $foundLogo" 'INFO'
				Write-Host "Upload logo '$([System.IO.Path]::GetFileName($foundLogo))' with '$displayName'? " -ForegroundColor Magenta -NoNewline
				$logoResp = Read-Host "[Y/n]"
				if (-not $logoResp -or $logoResp.Trim() -notmatch '^[Nn]') {
					$logoPath = $foundLogo
					Write-Log "Will upload logo for '$displayName': $logoPath" 'INFO'
				} else {
					Write-Log "User declined logo upload for '$displayName'" 'INFO'
				}
			}
		} else {
			Write-Log "Dry-run: would search for logo in AppLogos for '$displayName'" 'INFO'
		}
	} catch { Write-Log "Logo prompt failed for '$displayName': $($_.Exception.Message)" 'WARN' }

	# First check if user provided a logo from AppLogos, otherwise look in package directory
	if ($logoPath) {
		$img = Get-Item -Path $logoPath -ErrorAction SilentlyContinue
	} else {
		$img = Get-ChildItem -Path $p.DirectoryName -Include *.png,*.jpg,*.jpeg,*.ico -File -ErrorAction SilentlyContinue | Select-Object -First 1
	}
	if ($img -and (Get-Command -Name New-IntuneWin32AppIcon -ErrorAction SilentlyContinue)) { try { $iconObj = New-IntuneWin32AppIcon -FilePath $img.FullName; Write-Log "Created Icon object from: $($img.FullName)" 'INFO' } catch { } }

	# Prompt for custom return codes (optional)
	if (-not $useAnswers) {
		$returnCodes = @()
		if (-not $DryRun -and (Get-Command -Name New-IntuneWin32AppReturnCode -ErrorAction SilentlyContinue)) {
			Write-Host "Add custom return codes for '$displayName'? (e.g., '1337:retry', '3010:softReboot', leave blank to skip) " -ForegroundColor Cyan -NoNewline
			$rcResp = Read-Host "[blank to skip]"
			if ($rcResp -and $rcResp.Trim()) {
				try {
					$rcEntries = $rcResp.Split(',')
					foreach ($rcEntry in $rcEntries) {
						$rcTrimmed = $rcEntry.Trim()
						if ($rcTrimmed -match '^(\\d+):(.+)$') {
							$code = [int]$Matches[1]
							$type = $Matches[2].Trim()
							try {
								$rc = New-IntuneWin32AppReturnCode -ReturnCode $code -Type $type
								$returnCodes += $rc
								Write-Log "Added return code: $code ($type)" 'INFO'
							} catch {
								Write-Log "Failed to create return code $code ($type): $($_.Exception.Message)" 'WARN'
							}
						}
					}
				} catch {
					Write-Log "Return code parsing failed: $($_.Exception.Message)" 'WARN'
				}
			}
		} else {
			Write-Log "Dry-run: would prompt for return codes for '$displayName'" 'INFO'
		}
	} else {
		Write-Log "Using saved return codes for '$displayName'" 'INFO'
	}

	# write sidecar metadata
	try { $metaPath = Join-Path $p.DirectoryName ($p.BaseName + '.detection.json'); $detection | ConvertTo-Json -Depth 4 | Out-File -FilePath $metaPath -Encoding utf8; Write-Log "Wrote detection metadata to $metaPath" 'INFO' } catch { }

	# Per-package uninstall mode prompt (include package/display name)
	$uninstallCmd = $DefaultUninstallCmd
	try {
		if ($useAnswers) {
			Write-Log "Using saved uninstall mode for '$displayName'" 'INFO'
		} elseif (-not $DryRun) {
			Write-Host "Uninstall mode for '$displayName' ($($p.Name)): [S]ilent or [N]onInteractive? " -ForegroundColor Cyan -NoNewline
			$uResp = Read-Host "[S]/N"
			if ($uResp -and $uResp.Trim() -match '^[Nn]') {
				$uninstallCmd = '.\\Invoke-AppDeployToolkit.exe -DeploymentType Uninstall -DeployMode NonInteractive'
				Write-Log "Uninstall mode for '$displayName' set to NonInteractive" 'INFO'
			} else {
				Write-Log "Uninstall mode for '$displayName' set to Silent" 'INFO'
			}
		} else {
			Write-Log "Dry-run: would prompt for uninstall mode for '$displayName'" 'INFO'
		}
	} catch { Write-Log "Uninstall mode prompt failed for '$displayName': $($_.Exception.Message)" 'WARN' }

	# Per-package assignment group prompts (Required, Available). Available options: Company-Portal, CPT, or Skip.
	try {
		if (-not $DryRun) {
			Write-Host "Enter Required assignment groups for '$displayName' ($($p.Name)) as comma-separated names (or press Enter to skip): " -ForegroundColor Yellow -NoNewline
			$reqResp = Read-Host
			if ($reqResp -and $reqResp.Trim() -ne '') { $requiredGroups = $reqResp -split ',' | ForEach-Object { $_.Trim() } }
			Write-Host "Select Available assignment for '$displayName' ($($p.Name)) - choose: [1] Company-Portal  [2] CPT  [Enter] Skip: " -ForegroundColor Green -NoNewline
			$availResp = Read-Host "Enter 1, 2, or press Enter to skip"
			switch ($availResp.Trim()) {
				'1' { $availableGroups = @('Company-Portal'); break }
				'2' { $availableGroups = @('CPT'); break }
				default { $availableGroups = @() }
			}
			Write-Log "Assignment groups for '$displayName' -> Required: $([string]::Join(',', $requiredGroups)) ; Available: $([string]::Join(',', $availableGroups))" 'INFO'
		} else {
			Write-Log "Dry-run: would prompt for assignment groups for '$displayName' (Available options: Company-Portal, CPT, or Skip)" 'INFO'
		}
	} catch { Write-Log "Assignment group prompt failed for '$displayName': $($_.Exception.Message)" 'WARN' }

		# Offer to save these answers for future runs (only if we didn't load answers)
		if (-not $useAnswers -and -not $DryRun) {
			try {
				Write-Host "Save these answers for future uploads of '$displayName'? (Y/n) " -ForegroundColor Cyan -NoNewline
				$saveResp = Read-Host
				if (-not $saveResp -or $saveResp.Trim() -match '^[Yy]') {
					$saveObj = [PSCustomObject]@{
						UninstallCmd = $uninstallCmd
						LogoPath = $logoPath
						RequiredGroups = $requiredGroups
						AvailableGroups = $availableGroups
						ReturnCodes = @()
					}
					if ($returnCodes) {
						foreach ($rc in $returnCodes) {
							if ($rc -is [string]) { $saveObj.ReturnCodes += $rc } elseif ($rc.PSObject.Properties.Name -contains 'ReturnCode') { $saveObj.ReturnCodes += ("$($rc.ReturnCode):$($rc.Type)") } else { $saveObj.ReturnCodes += $rc.ToString() }
						}
					}
					$saveJson = $saveObj | ConvertTo-Json -Depth 5
					$saveJson | Out-File -FilePath $answerFile -Encoding utf8
					Write-Log "Saved answers to $answerFile" 'INFO'
				}
			} catch { Write-Log "Failed to save answers file ${answerFile}: $($_.Exception.Message)" 'WARN' }
		}

	# prepare parameters
	$invokeParams = @{
		FilePath = $p.FullName
		DisplayName = $displayName
		Description = $description
		Publisher = $Publisher
		InstallExperience = 'system'
		RestartBehavior = 'suppress'
		InstallCommandLine = $DefaultInstallCmd
		UninstallCommandLine = $uninstallCmd
		Notes = 'Uploaded via CI\CD Pipeline'
		Owner = 'Tyler Cox'
	}
	if ($detectionRule) {
		$isOrdered = $false
		if ($detectionRule -is [System.Collections.Specialized.OrderedDictionary]) { $isOrdered = $true }
		elseif ($detectionRule -is [System.Array]) {
			$bad = $false
			foreach ($el in $detectionRule) { if (-not ($el -is [System.Collections.Specialized.OrderedDictionary])) { $bad = $true; break } }
			if (-not $bad) { $isOrdered = $true }
		}
		if ($isOrdered) {
			$invokeParams['DetectionRule'] = $detectionRule
		} else {
			Write-Log "DetectionRule exists but is not the expected OrderedDictionary type; skipping passing DetectionRule" 'WARN'
		}
	}
	if ($requirementRule) {
		if ($requirementRule -is [System.Collections.Specialized.OrderedDictionary] -or ($requirementRule -is [System.Array] -and ($requirementRule | ForEach-Object { $_ -is [System.Collections.Specialized.OrderedDictionary] } | Where-Object { $_ -eq $false } | Measure-Object).Count -eq 0)) {
			$invokeParams['RequirementRule'] = $requirementRule
		} else {
			Write-Log "RequirementRule exists but is not the expected OrderedDictionary type; skipping passing RequirementRule" 'WARN'
		}
	}
	if ($iconObj) { $invokeParams['Icon'] = $iconObj }
	if ($returnCodes -and $returnCodes.Count -gt 0) { $invokeParams['ReturnCode'] = $returnCodes }

	$paramStr = ($invokeParams.GetEnumerator() | ForEach-Object { "-$($_.Key) '$($_.Value) '" }) -join ' '
	Write-Log "Prepared Add-IntuneWin32App with params: $paramStr"

	# Queue or skip the package (DryRun still queues but will not perform uploads)
	$queue = $true
	if ($DryRun) {
		Write-Log "Dry-run: would queue $($p.Name) for upload (no actual upload)" 'INFO'
		$queue = $true
	} elseif (-not $Force) {
		Write-Host "Queue upload $($p.Name) as '$displayName'? " -ForegroundColor Cyan -NoNewline
		$ok = Read-Host "[(Y/n]"
		if ($ok -and $ok.Trim() -match '^[Nn]') { Write-Log "Skipping $($p.Name) by user choice"; $queue = $false }
	}

	if ($queue) {
		$plannedUploads += [PSCustomObject]@{
			File = $p
			DisplayName = $displayName
			InvokeParams = $invokeParams
			ParamStr = $paramStr
			RequiredGroups = $requiredGroups
			AvailableGroups = $availableGroups
		}
	}
}

# After collecting per-package decisions, perform uploads (unless DryRun)
if (-not $plannedUploads -or $plannedUploads.Count -eq 0) {
	Write-Log 'No packages queued for upload; exiting' 'INFO'
	Write-Log 'All done.'
	exit 0
}

$queuedNames = $plannedUploads | ForEach-Object { $_.DisplayName }
$queuedList = $queuedNames -join ', '
Write-Log "Queued packages for upload: $queuedList" 'INFO'

if ($DryRun) {
	Write-Log 'Dry-run: no uploads will be performed. Exiting after listing queued packages.' 'INFO'
	Write-Log 'All done.'
	exit 0
}

# Final confirmation before uploading all queued packages
if (-not $Force) {
	Write-Host "Proceed to upload $($plannedUploads.Count) queued packages to Intune? " -ForegroundColor Green -NoNewline
	$final = Read-Host "[(Y/n]"
	if ($final -and $final.Trim() -match '^[Nn]') { Write-Log 'User cancelled bulk upload'; Write-Log 'All done.'; exit 0 }
}

foreach ($entry in $plannedUploads) {
	$p = $entry.File
	$displayName = $entry.DisplayName
	$invokeParamsForCall = $entry.InvokeParams
	$requiredGroups = $entry.RequiredGroups
	$availableGroups = $entry.AvailableGroups
	try {
		$app = Add-IntuneWin32App @invokeParamsForCall -Verbose -ErrorAction Stop
		Write-Log "Uploaded $($p.Name) to Intune (DisplayName: $displayName)" 'INFO'
		
		# Assign groups if app was created successfully and assignment groups were specified
		if ($app -and $app.Id) {
			# Resolve group name to Entra ID group ID
			function Resolve-GroupId {
				param([string]$Name)
				$nm = $Name.Trim('"')
				while ($true) {
					# Try Microsoft Graph (Get-MgGroup)
					if (Get-Command -Name Get-MgGroup -ErrorAction SilentlyContinue) {
						try {
							$escaped = $nm -replace "'","''"
							$g = Get-MgGroup -Filter "displayName eq '$escaped'" -ErrorAction Stop
							if ($g) { return @{ Name = $g.DisplayName; Id = $g.Id } }
						} catch { }
						try { $g2 = Get-MgGroup -Search $nm -ErrorAction SilentlyContinue; if ($g2) { return @{ Name = $g2.DisplayName; Id = $g2.Id } } } catch { }
					}

					# Try AzureAD (Get-AzureADGroup)
					if (Get-Command -Name Get-AzureADGroup -ErrorAction SilentlyContinue) {
						try { $g3 = Get-AzureADGroup -SearchString $nm -ErrorAction SilentlyContinue; if ($g3) { return @{ Name = $g3.DisplayName; Id = $g3.ObjectId } } } catch { }
					}

					# Could not resolve programmatically - ask user for corrected name or an ID, or blank to skip
					Write-Host "Group '$nm' not found. Enter a different group name or paste the group ID (leave blank to skip):" -ForegroundColor Yellow -NoNewline
					$resp = Read-Host
					if (-not $resp) { return $null }
					$nm = $resp.Trim('"')
				}
			}

			# Assign-AppGroups: Assign a set of groups to an app with a given intent (required/available)
			function Assign-AppGroups {
				param([string]$AppId, [string[]]$Groups, [string]$Intent)
				if (-not $Groups -or $Groups.Count -eq 0) { return }

				# Check for all-user/all-device special cases
				$allUsersCmdlet = Get-Command -Name Add-IntuneWin32AppAssignmentAllUsers -ErrorAction SilentlyContinue
				$allDevicesCmdlet = Get-Command -Name Add-IntuneWin32AppAssignmentAllDevices -ErrorAction SilentlyContinue
				$groupCmdlet = Get-Command -Name Add-IntuneWin32AppAssignmentGroup -ErrorAction SilentlyContinue

				foreach ($group in $Groups) {
					# Check for special cases first
					if ($group -match '^(All\s*Users?)$') {
						if ($allUsersCmdlet) {
							try {
								Add-IntuneWin32AppAssignmentAllUsers -ID $AppId -Intent $Intent -Notification "showAll" -ErrorAction Stop
								Write-Log "Assigned $Intent to 'All Users' for $displayName" 'INFO'
								continue
							} catch {
								Write-Log "Failed to assign $Intent to All Users: $($_.Exception.Message)" 'WARN'
								continue
							}
						}
					}
					elseif ($group -match '^(All\s*Devices?)$') {
						if ($allDevicesCmdlet) {
							try {
								Add-IntuneWin32AppAssignmentAllDevices -ID $AppId -Intent $Intent -Notification "showAll" -ErrorAction Stop
								Write-Log "Assigned $Intent to 'All Devices' for $displayName" 'INFO'
								continue
							} catch {
								Write-Log "Failed to assign $Intent to All Devices: $($_.Exception.Message)" 'WARN'
								continue
							}
						}
					}

					# Regular group assignment
					$resolved = Resolve-GroupId -Name $group
					if (-not $resolved) { Write-Log "Skipping assignment for group input '$group' (not resolved)." 'WARN'; continue }
					
					if ($groupCmdlet) {
						try {
							Add-IntuneWin32AppAssignmentGroup -Include -ID $AppId -GroupID $resolved.Id -Intent $Intent -Notification "showAll" -ErrorAction Stop
							Write-Log "Assigned $Intent group '$($resolved.Name)' (Id: $($resolved.Id)) to $displayName" 'INFO'
						} catch {
							Write-Log "Failed to assign $Intent group '$($resolved.Name)' : $($_.Exception.Message)" 'WARN'
						}
					} else {
						Write-Log "Add-IntuneWin32AppAssignmentGroup not available - cannot assign group '$($resolved.Name)'" 'WARN'
					}
				}
			}

			Assign-AppGroups -AppId $app.Id -Groups $requiredGroups -Intent "required"
			Assign-AppGroups -AppId $app.Id -Groups $availableGroups -Intent "available"
		}
	} catch {
		Write-Log "Failed to upload $($p.Name): $($_.Exception.Message)" 'ERROR'
	}
}

Write-Log 'All done.'

