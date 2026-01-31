**Overview**
- **Upload-IntunePackages.ps1**: Scans an upload folder for .intunewin packages, uploads each app to Intune, prompts for per-app options (icons, group assignments, return codes detection rules) and can save/reuse answer files.  
- **Create-IntunePackages.ps1**: Recursively Scans your Packages dir for PSADT apps and packages installers and metadata into .intunewin files (prepares Win32 app packages) for consumption by the uploader.
