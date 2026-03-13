# IntuneStuff

Personal GitHub repository for building and uploading Microsoft Intune Win32 app packages.

## Overview

- `Create-IntunePackages.ps1`: Recursively scans your package source folders and builds `.intunewin` payloads for Win32 app deployment.
- `Upload-IntunePackages.ps1`: Processes built packages and uploads them to Intune with interactive options (icons, assignments, return codes, detection rules) and answer-file reuse.

## Typical Workflow

1. Build packages with `Create-IntunePackages.ps1`.
2. Validate package output and metadata.
3. Upload with `Upload-IntunePackages.ps1`.
4. Commit script updates and documentation changes to this repo.

## Notes

- This is a personal repository; keep secrets and tokens out of source control.
- Use environment variables or local secure storage for credentials.
- This repository is for scripts and documentation.