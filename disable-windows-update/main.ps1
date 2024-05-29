<# 
.SYNOPSIS
    Disable Windows Update.

.DESCRIPTION 
    Disable services for Windows Update and set Registry, Scheduled Tasks to (hopefully) keep them disabled.
 
.NOTES 
    Needs to run as administrator.
#>

. {Invoke-WebRequest https://raw.githubusercontent.com/lwarnt/fix-windows/main/disclaimer.ps1 } | Invoke-Expression

function disableWindowsUpdate {
    Disable-ScheduledTask -TaskName "\Microsoft\Windows\WindowsUpdate\Scheduled Start" | Out-Null
    # Modify UX
    if (!(Test-Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings")){
        New-Item -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1
    
    if(!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate")){
	    New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    }
    # disable access
    New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Value 1 -PropertyType DWORD -Force | Out-Null
    # disable auto update
    if(!(Test-Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")){
	    New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
}
function disableMedic {
    # disable medic
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WaaSMedicSvc" -Name Start -Value 4

    # Take ownership and modifies discretionary access control lists 
    # HINT: this will work for 'en' but not for other languages, because group names are localized :/
    takeown /F C:\Windows\System32\Tasks\Microsoft\Windows\WaaSMedic /A /R
    icacls C:\Windows\System32\Tasks\Microsoft\Windows\WaaSMedic /grant Administrators:F /T

    Get-ScheduledTask -TaskPath "\Microsoft\Windows\WaaSMedic\" | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null

    # delete the trigger for medic service
    $service = New-Object -ComObject Schedule.Service
    $service.Connect($env:COMPUTERNAME)

    $folder = $service.GetFolder('\Microsoft\Windows\WaaSMedic')

    $task = $folder.GetTask("PerformRemediation")
    $task.Definition.Triggers.Remove(1)

    $folder.RegisterTaskDefinition($task.Name, $task.Definition, 4, $null, $null, $null) | Out-Null
}
function disableOrchestrator {        
    # Take ownership and modifies discretionary access control lists 
    # HINT: this will work for 'en' but not for other languages, because group names are localized :/
    takeown /F C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator /A /R
    icacls C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator /grant Administrators:F /T

    Get-ScheduledTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
}
function scheduleDisableWindowsUpdate {
    # scheduled task to disable Windows Update in case it somehow re-activates itself
    $repeat = (New-TimeSpan -Hours 8)
    $duration = (New-TimeSpan -Days 365)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration
    $arg = "Stop-Service -Name wuauserv;Set-Service -Name wuauserv -StartupType Disabled"
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
    Register-ScheduledTask DisableWindowsUpdate -Principal $principal -Action $action -Trigger $trigger -ErrorAction SilentlyContinue | Out-Null
    # scheduled task to stop Medic Service in case it somehow re-activates itself
    $repeat1 = (New-TimeSpan -Hours 8)
    $duration1 = (New-TimeSpan -Days 365)
    $trigger1 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat1 -RepetitionDuration $duration1
    $arg1 = "Stop-Service -Name WaaSMedicSvc;Set-Service -Name WaaSMedicSvc -StartupType Disabled"
    $principal1 = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $action1 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg1
    Register-ScheduledTask DisableWindowsUpdateMedic -Principal $principal1 -Action $action1 -Trigger $trigger1 -ErrorAction SilentlyContinue | Out-Null
}

$services = @("wuauserv", "WaaSMedicSvc", "UsoSvc") 
$services | ForEach-Object{
    Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Stop-Service -Name $_ -ErrorAction SilentlyContinue | Out-Null
}
Stop-Process -Name "MoUsoCoreWorker" -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
Stop-Process -Name "TiWorker" -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
# Set various properties
disableWindowsUpdate
disableMedic
disableOrchestrator
# schedule additional tasks
scheduleDisableWindowsUpdate
