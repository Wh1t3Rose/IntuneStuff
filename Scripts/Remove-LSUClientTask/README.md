# Remove-LSUClientTask

## Scripts
- `Detect-LSUClientTaskRemoved.ps1`: Intune Win32 detection script for removed LSUClient scheduled task.
- `Remove-LSUClientTask.ps1`: Removes the scheduled task named VACO-LSUClient-PatchTuesday.

## Usage
Run in PowerShell with the required permissions and dependencies.

## Script Notes
### `Detect-LSUClientTaskRemoved.ps1`
- Synopsis: Intune Win32 detection script for removed LSUClient scheduled task.
- Description: Detects whether scheduled task 'VACO-LSUClient-PatchTuesday' is absent. Returns success for Intune detection when the task does NOT exist.

### `Remove-LSUClientTask.ps1`
- Synopsis: Removes the scheduled task named VACO-LSUClient-PatchTuesday.
