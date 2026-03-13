# Create-WinISO

Build a customized Windows Pro ISO with injected drivers, automated tool handling, and interactive or non-interactive workflows.

**Summary**
- A PowerShell utility to extract, modify (inject drivers), and rebuild a bootable Windows Pro ISO (BIOS + UEFI).
- Automates common tasks: ADK/oscdimg discovery or install, ISO download (via DL-WinISO), and fallback to the Media Creation Tool.

**Features**
- Interactive menu with modes: Automatic, Download ISO, Select Drivers, Build.
- Reuses existing ADK installer (adksetup.exe) if present; optional silent install with progress.
- Handles ADK silent-install rate limiting (exit code 1001) with retry and warnings.
- Downloads and runs `DL-WinISO.ps1` locally to obtain Microsoft CDN ISO URLs; detects rate-limit responses and prompts for manual ISO.
- If automatic download fails, downloads the Media Creation Tool (MCT), launches it elevated, and prompts for the resulting ISO.
- Driver selection and injection into the image using DISM; rebuilds a bootable ISO with `oscdimg.exe`.

**Requirements**
- Windows (script must be run as Administrator).
- PowerShell (Windows PowerShell or PowerShell Core).
- Network access for downloads (ADK, DL-WinISO, MCT, ISO).
- `DISM`, `Mount-DiskImage` available on the host.
- `oscdimg.exe` (Windows ADK Deployment Tools) — the script can help download/install it.

**Quick Start**
- Interactive (recommended):

  powershell -NoProfile -ExecutionPolicy Bypass -File Packaging/!PS-Scripts/Create-WinISO.ps1

- Non-interactive (CI-style):

  pwsh -File Packaging/!PS-Scripts/Create-WinISO.ps1 -NonInteractive -IsoPath 'C:\isos\win11.iso' -OscdimgPath 'C:\Tools\oscdimg.exe'

**Parameters**
- `-BuildRoot` : (string) Override build root directory. Default: `C:\Build`.
- `-Drivers` : (string) Path to drivers folder. Default: `C:\Build\Drivers`.
- `-IsoPath` : (string) Path to an existing Windows ISO (used in non-interactive mode).
- `-OscdimgPath` : (string) Explicit path to `oscdimg.exe`.
- `-NonInteractive` : (switch) Run without interactive prompts (fail fast on missing inputs).
- `-DryRun` : (switch) Show actions without performing changes.
- `-AutoInstallAdk` : (switch) Attempt unattended ADK install when missing.
- `-AdkFeatures` : (string[]) Features to install with ADK (default: `('Deployment Tools','Imaging and Configuration Designer')`).

**ADK / oscdimg behavior**
- The script tries to locate `oscdimg.exe` by parameter, default path, or common Windows Kits locations.
- If not found, `Ensure-Oscdimg` offers to download `adksetup.exe` to `%TEMP%` and:
  - Reuse an existing `adksetup.exe` if present.
  - Offer Interactive or Silent install. Silent installs run with `/quiet /norestart /ceip off` and limited features.
  - On silent-install exit code `1001` (rate limit), the script retries with exponential backoff and warns the user.
  - If automated install fails, falls back to opening the ADK download page and prompting the user.

**ISO Download behavior (DL-WinISO & MCT fallback)**
- When choosing "Download ISO", the script downloads `DL-WinISO.ps1` (from the script folder) and runs it locally with parameters to obtain CDN URLs.
- The script detects the rate-limit message `Error: We are unable to complete your request at this time` and will prompt the user to provide a manually downloaded ISO if rate-limited.
- If `DL-WinISO` does not produce an ISO, the script downloads the Microsoft Media Creation Tool (MCT) after a 3-second notice, launches it elevated, and prompts the user to supply the created ISO path.

**Driver injection & ISO build**
- Drivers copied into the `Drivers` folder are injected into the `install.wim`/`install.esd` image via DISM.
- The script mounts the image, injects drivers recursively from the `Drivers` folder, commits changes, converts back to ESD if needed, and runs `oscdimg.exe` to produce a bootable ISO (`Windows11_VACO.iso` by default).

**Troubleshooting**
- Run the script as Administrator.
- If ADK silent install fails repeatedly with exit code 1001, wait a while or download ADK manually from Microsoft and run the installer interactively.
- If `DL-WinISO` is rate-limited, download the ISO using another machine/network or use the Media Creation Tool as prompted.
- Review logs under `%TEMP%\adk_install_logs` for ADK installer stdout when diagnosing install issues.

**Contributing**
- Bug reports and improvements welcome. Keep changes focused and preserve interactive UX.
- If you update behavior for ADK/MCT flows or DL-WinISO integration, update the changelog in `Create-WinISO.ps1`.

**Notes**
- The script is designed to be interactive-first, but supports non-interactive automation with `-NonInteractive` and explicit paths.
- Many operations (ADK install, DISM, oscdimg) require elevation and may modify system state; test in an isolated environment when possible.

---

If you'd like, I can also add example GitHub Actions to run a non-interactive smoke test or expand the README with troubleshooting screenshots and log examples.
