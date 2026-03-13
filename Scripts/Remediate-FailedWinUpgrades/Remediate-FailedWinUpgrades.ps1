<#
.SYNOPSIS
Brief description for Remediate-FailedWinUpgrades.ps1

.DESCRIPTION
Add a longer description for Remediate-FailedWinUpgrades.ps1 here.

.PARAMETER
Optional parameters (if any).

.EXAMPLE
.\Remediate-FailedWinUpgrades.ps1

.INPUTS
None.

.OUTPUTS
None.

.NOTES
Author: Tyler Cox
Created: 2025-10-14
Blog: blog.tylercox.tech
#>
#Run DISM
try {Repair-WindowsImage -RestoreHealth -NoRestart -Online -LogPath "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediation\DISM.log" -Verbose -ErrorAction SilentlyContinue}
catch {Write-Output "DISM error occurred. Check logs"}
finally {
        #Check registry for pauses
        $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $TestPath = Test-Path $Path
        if  ($TestPath -eq $true)
            {
            Write-Output "Deleting $Path"
            Remove-Item -Path $Path -Recurse -Verbose
            }

        $key = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings"
        $TestKey = Test-Path $key
        if  ($TestKey -eq $true)
            {
            $val = (Get-Item $key -EA Ignore);
            $PausedQualityDate = (Get-Item $key -EA Ignore).Property -contains "PausedQualityDate"
            $PausedFeatureDate = (Get-Item $key -EA Ignore).Property -contains "PausedFeatureDate"
            $PausedQualityStatus = (Get-Item $key -EA Ignore).Property -contains "PausedQualityStatus"
            $PausedQualityStatusValue = $val.GetValue("PausedQualityStatus");
            $PausedFeatureStatus = (Get-Item $key -EA Ignore).Property -contains "PausedFeatureStatus"
            $PausedFeatureStatusValue = $val.GetValue("PausedFeatureStatus");

            if  ($PausedQualityDate -eq $true)
                {
                Write-Output "PausedQualityDate under $key present"
                Remove-ItemProperty -Path $key -Name "PausedQualityDate" -Verbose -ErrorAction SilentlyContinue
                $PausedQualityDate = (Get-Item $key -EA Ignore).Property -contains "PausedQualityDate"
                }

            if  ($PausedFeatureDate -eq $true)
                {
                Write-Output "PausedFeatureDate under $key present"
                Remove-ItemProperty -Path $key -Name "PausedFeatureDate" -Verbose -ErrorAction SilentlyContinue
                $PausedFeatureDate = (Get-Item $key -EA Ignore).Property -contains "PausedFeatureDate"
                }

            if  ($PausedQualityStatus -eq $true)
                {
                Write-Output "PausedQualityStatus under $key present"
                Write-Output "Currently set to $PausedQualityStatusValue"
                if  ($PausedQualityStatusValue -ne "0")
                    {
                    Set-ItemProperty -Path $key -Name "PausedQualityStatus" -Value "0" -Verbose
                    $PausedQualityStatusValue = $val.GetValue("PausedQualityStatus");
                    }
                }

            if  ($PausedFeatureStatus -eq $true)
                {
                Write-Output "PausedFeatureStatus under $key present"
                Write-Output "Currently set to $PausedFeatureStatusValue"
                if  ($PausedFeatureStatusValue -ne "0")
                    {
                    Set-ItemProperty -Path $key -Name "PausedFeatureStatus" -Value "0" -Verbose
                    $PausedFeatureStatusValue = $val.GetValue("PausedFeatureStatus");
                    }
                }
            }

        $key2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update"
        $TestKey2 = Test-Path $key2
        if  ($TestKey2 -eq $true)
            {
            $val2 = (Get-Item $key2 -EA Ignore);

            $PauseQualityUpdatesStartTime = (Get-Item $key2 -EA Ignore).Property -contains "PauseQualityUpdatesStartTime"
            $PauseFeatureUpdatesStartTime = (Get-Item $key2 -EA Ignore).Property -contains "PauseFeatureUpdatesStartTime"
            $PauseQualityUpdates = (Get-Item $key2 -EA Ignore).Property -contains "PauseQualityUpdates"
            $PauseQualityUpdatesValue = $val2.GetValue("PauseQualityUpdates");
            $PauseFeatureUpdates = (Get-Item $key2 -EA Ignore).Property -contains "PauseFeatureUpdates"
            $PauseFeatureUpdatesValue = $val2.GetValue("PauseFeatureUpdates");
            $DeferFeatureUpdates = (Get-Item $key2 -EA Ignore).Property -contains "DeferFeatureUpdatesPeriodInDays"
            $DeferFeatureUpdatesValue = $val2.GetValue("DeferFeatureUpdatesPeriodInDays");

            if  ($DeferFeatureUpdates -eq $true)
                {
                Write-Output "DeferFeatureUpdatesPeriodInDays under $key2 present"
                Write-Output "Currently set to $DeferFeatureUpdatesValue"
                if  ($DeferFeatureUpdatesValue -ne "0")
                    {
                    Set-ItemProperty -Path $key2 -Name "DeferFeatureUpdatesPeriodInDays" -Value "0" -Verbose
                    $DeferFeatureUpdatesValue = $val2.GetValue("DeferFeatureUpdatesPeriodInDays");
                    }
                }    

            if  ($PauseQualityUpdatesStartTime -eq $true)
                {
                Write-Output "PauseQualityUpdatesStartTime under $key2 present"
                Remove-ItemProperty -Path $key2 -Name "PauseQualityUpdatesStartTime" -Verbose -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $key2 -Name "PauseQualityUpdatesStartTime_ProviderSet" -Verbose -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $key2 -Name "PauseQualityUpdatesStartTime_WinningProvider" -Verbose -ErrorAction SilentlyContinue
                $PauseQualityUpdatesStartTime = (Get-Item $key2 -EA Ignore).Property -contains "PauseQualityUpdatesStartTime"
                }

            if  ($PauseFeatureUpdatesStartTime -eq $true)
                {
                Write-Output "PauseFeatureUpdatesStartTime under $key2 present"
                Remove-ItemProperty -Path $key2 -Name "PauseFeatureUpdatesStartTime" -Verbose -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $key2 -Name "PauseFeatureUpdatesStartTime_ProviderSet" -Verbose -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $key2 -Name "PauseFeatureUpdatesStartTime_WinningProvider" -Verbose -ErrorAction SilentlyContinue
                $PauseFeatureUpdatesStartTime = (Get-Item $key2 -EA Ignore).Property -contains "PauseFeatureUpdatesStartTime"
                }

            if  ($PauseQualityUpdates -eq $true)
                {
                Write-Output "PauseQualityUpdates under $key2 present"
                Write-Output "Currently set to $PauseQualityUpdatesValue"
                if  ($PauseQualityUpdatesValue -ne "0")
                    {
                    Set-ItemProperty -Path $key2 -Name "PauseQualityUpdates" -Value "0" -Verbose
                    $PauseQualityUpdatesValue = $val2.GetValue("PausedQualityStatus");
                    }
                }

            if  ($PauseFeatureUpdates -eq $true)
                {
                Write-Output "PauseFeatureUpdates under $key2 present"
                Write-Output "Currently set to $PauseFeatureUpdatesValue"
                if  ($PauseFeatureUpdatesValue -ne "0")
                    {
                    Set-ItemProperty -Path $key2 -Name "PauseFeatureUpdates" -Value "0" -Verbose
                    $PauseFeatureUpdatesValue = $val2.GetValue("PauseFeatureUpdates");
                    }
                }
            }

        $key3 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        $TestKey3 = Test-Path $key3
        if  ($TestKey3 -eq $true)
            {
            $val3 = (Get-Item $key3 -EA Ignore);

            $AllowDeviceNameInTelemetry = (Get-Item $key3 -EA Ignore).Property -contains "AllowDeviceNameInTelemetry"
            $AllowTelemetry_PolicyManager = (Get-Item $key3 -EA Ignore).Property -contains "AllowTelemetry_PolicyManager"
            $AllowDeviceNameInTelemetryValue = $val3.GetValue("AllowDeviceNameInTelemetry");
            $AllowTelemetry_PolicyManagerValue = $val3.GetValue("AllowTelemetry_PolicyManager");

            if  ($AllowDeviceNameInTelemetry -eq $true)
                {
                Write-Output "AllowDeviceNameInTelemetry under $key3 present"
                Write-Output "Currently set to $AllowDeviceNameInTelemetryValue"
                }
            else{New-ItemProperty -Path $key3 -PropertyType DWORD -Name "AllowDeviceNameInTelemetry" -Value "1" -Verbose}

            if  ($AllowDeviceNameInTelemetryValue -ne "1")
                {Set-ItemProperty -Path $key3 -Name "AllowDeviceNameInTelemetry" -Value "1" -Verbose}

            if  ($AllowTelemetry_PolicyManager -eq $true)
                {
                Write-Output "AllowTelemetry_PolicyManager under $key3 present"
                Write-Output "Currently set to $AllowTelemetry_PolicyManagerValue"
                }
            else{New-ItemProperty -Path $key3 -PropertyType DWORD -Name "AllowTelemetry_PolicyManager" -Value "1" -Verbose}

            if  ($AllowTelemetry_PolicyManagerValue -ne "1")
                {Set-ItemProperty -Path $key3 -Name "AllowTelemetry_PolicyManager" -Value "1" -Verbose}
            }


        $key4 = "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX"
        $TestKey4 = Test-Path $key4
        if  ($TestKey4 -eq $true)
            {
            $val4 = (Get-Item $key4 -EA Ignore);

            $GStatus = (Get-Item $key4 -EA Ignore).Property -contains "GStatus"
            $GStatusValue = $val4.GetValue("GStatus");
            
            if  ($GStatus -eq $true) 
                {
                Write-Output "GStatus under $key4 present"
                Write-Output "Currently set to $GStatusValue"
                }
            else{New-ItemProperty -Path $key4 -PropertyType DWORD -Name "GStatus" -Value "2" -Verbose}

            if  ($GStatusValue -ne "2")
                {Set-ItemProperty -Path $key4 -Name "GStatus" -Value "2" -Verbose}
            }

        Write-Host "1. Stopping Windows Update Services..." 
        Stop-Service -Name BITS -Force -Verbose -ErrorAction SilentlyContinue
        Stop-Service -Name wuauserv -Force -Verbose -ErrorAction SilentlyContinue
        Stop-Service -Name cryptsvc -Force -Verbose -ErrorAction SilentlyContinue

        Write-Host "2. Remove QMGR Data file..." 
        Remove-Item -Path "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue -Verbose

        Write-Host "3. Removing the Software Distribution and CatRoot Folder..." 
        Remove-Item -Path "$env:systemroot\SoftwareDistribution" -ErrorAction SilentlyContinue -Recurse -Verbose
        Remove-Item -Path "$env:systemroot\System32\Catroot2" -ErrorAction SilentlyContinue -Recurse -Verbose

        Write-Host "4. Resetting the Windows Update Services to default settings..." 
        Start-Process "sc.exe" -ArgumentList "sdset bits D:(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
        Start-Process "sc.exe" -ArgumentList "sdset wuauserv D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)"

        Set-Location $env:systemroot\system32 

        Write-Host "5. Registering some DLLs..." 
        regsvr32.exe atl.dll /s
        regsvr32.exe urlmon.dll /s
        regsvr32.exe mshtml.dll /s
        regsvr32.exe shdocvw.dll /s
        regsvr32.exe browseui.dll /s
        regsvr32.exe jscript.dll /s
        regsvr32.exe vbscript.dll /s
        regsvr32.exe scrrun.dll /s
        regsvr32.exe msxml.dll /s
        regsvr32.exe msxml3.dll /s
        regsvr32.exe msxml6.dll /s
        regsvr32.exe actxprxy.dll /s
        regsvr32.exe softpub.dll /s
        regsvr32.exe wintrust.dll /s
        regsvr32.exe dssenh.dll /s
        regsvr32.exe rsaenh.dll /s
        regsvr32.exe gpkcsp.dll /s
        regsvr32.exe sccbase.dll /s
        regsvr32.exe slbcsp.dll /s
        regsvr32.exe cryptdlg.dll /s
        regsvr32.exe oleaut32.dll /s
        regsvr32.exe ole32.dll /s
        regsvr32.exe shell32.dll /s
        regsvr32.exe initpki.dll /s
        regsvr32.exe wuapi.dll /s
        regsvr32.exe wuaueng.dll /s
        regsvr32.exe wuaueng1.dll /s
        regsvr32.exe wucltui.dll /s
        regsvr32.exe wups.dll /s
        regsvr32.exe wups2.dll /s
        regsvr32.exe wuweb.dll /s
        regsvr32.exe qmgr.dll /s
        regsvr32.exe qmgrprxy.dll /s
        regsvr32.exe wucltux.dll /s
        regsvr32.exe muweb.dll /s
        regsvr32.exe wuwebv.dll /s

        Write-Host "6) Resetting the WinSock..." 
        netsh winsock reset 

        Write-Host "7) Starting Windows Update Services..." 
        Start-Service -Name BITS -Verbose
        Start-Service -Name wuauserv -Verbose 
        Start-Service -Name cryptsvc -Verbose

        Write-Host "8) Forcing discovery..."
        USOClient.exe StartInteractiveScan

        Write-Host "9) Pausing for 5 minutes"
        Start-Sleep -Seconds 300
        
        try { 
            Write-Host "10) Create diagnostic logs"
            $logs = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
            $OldLogs = "$logs\logs*.zip"
            $dir = "C:\BH IT\"
            $webClient = New-Object System.Net.WebClient
            $url = "https://go.microsoft.com/fwlink/?linkid=870142"
            $file = "$($dir)\SetupDiag.exe"
            $webClient.DownloadFile($url,$file)
            
            $checkLogs = Test-Path -Path $OldLogs
            if  ($checkLogs -eq $true)
                {Remove-Item -Path $OldLogs -Force -Recurse}

            ."$file" /Output:"$logs\#Windows Updates - Diagnostics.log"
            }
        catch {Write-Output "Diagnostic log creation failed. Check logs"}
        finally {
            Write-Host "11) Creating restart task for midnight"
            $TaskName = "MidnightShutdown"
            $Script = @'
                    $Last_reboot =  Get-ciminstance Win32_OperatingSystem | 
                    Select-Object -Exp LastBootUpTime   
                    # Check if fast boot is enabled: if enabled uptime may be wrong
                    $Check_FastBoot = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -ea silentlycontinue).HiberbootEnabled 
                    # If fast boot is not enabled
                    if  (($Null -eq $Check_FastBoot) -or ($Check_FastBoot -eq 0))
                        {
                        $Boot_Event =   Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot'| 
                                        Where-Object {$_.ID -eq 27 -and $_.message -like "*0x0*"}
                        If  ($null -ne $Boot_Event)
                            {$Last_boot = $Boot_Event[0].TimeCreated}
                        }

                    ElseIf  ($Check_FastBoot -eq 1)     
                            {
                            $Boot_Event =   Get-WinEvent -ProviderName 'Microsoft-Windows-Kernel-Boot'| 
                                            Where-Object {$_.ID -eq 27 -and $_.message -like "*0x1*"}
                            If  ($null -ne $Boot_Event)
                                {$Last_boot = $Boot_Event[0].TimeCreated}                       
                            }       
                        
                    If  ($null -eq $Last_boot)
                        {$Uptime = $Last_reboot}
                        
                    Else
                        {
                        If  ($Last_reboot -ge $Last_boot)
                            {$Uptime = $Last_reboot}            
                        Else
                            {$Uptime = $Last_boot}
                        }
                        
                    $Current_Date = get-date
                    $Diff_boot_time = $Current_Date - $Uptime
                    $Boot_Uptime_Days = $Diff_boot_time.TotalDays

                    if  ($Boot_Uptime_Days -lt "1")
                        {
                        Write-Host "There was a recent reboot"
                        }
                    else
                        {
                        shutdown.exe /r /f /t 300 /c "Your computer will restart in 5 minutes to install Windows updates. Please enter a OneSupport ticket if this prompt is displayed multiple days in a row."
                        }
'@

        #Encodes script block above so that it can be processed as a one-liner through the scheduled task
        $EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Script))

        #Creates scheduled task
        $action = (New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-noninteractive -windowstyle hidden -EncodedCommand $EncodedCommand")
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $trigger = New-ScheduledTaskTrigger -Once -At "23:59"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -Action $action -Trigger $trigger -Settings $Settings -Principal $principal -TaskName "$TaskName" -Description "Shuts down the computer at midnight" -Force
        }
    }


