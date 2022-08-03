<# 
.SYNOPSIS
    Disable Windows Update.

.DESCRIPTION 
    Disable services for Windows Update and set Registry, Scheduled Tasks to (hopefully) keep them disabled.
 
.NOTES 
    Needs to run as administrator.

.Parameter silent
    Do not ask for confirmation before running the script.

.Parameter force
    Ignore Restore Point creation failure.
#>
param(
    [Bool] $silent = $false,
    [Bool] $force = $false
)

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host "Run as Administrator" -ForegroundColor Red
    Pause
    Exit
}

# Disclaimer
if (! $silent){
    $disclaimer = "    THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, 
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES 
    OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    THIS SCRIPT DOES NOT COME WITH SUFFICIENT SAFEGUARDS.

    DO NOT PROCEED UNLESS YOU KNOW WHAT YOU ARE DOING.
    "
    Write-Host "`n$disclaimer`n`n" -ForegroundColor Yellow
    $confirmation = Read-Host "I accept these conditions and the risk. Proceed? [YES/NO]"
    while($confirmation -ne "YES"){
        if ($confirmation -eq 'NO') {
            Write-Host "Aborted." -ForegroundColor Red
            Pause
            Exit
        }
        $confirmation = Read-Host "I accept these conditions and the risk. Proceed? [YES/NO]"
    }
} else {
    Write-Host "Silent run. Skip confirmation." -ForegroundColor Yellow
    Write-Host "$disclaimer" -ForegroundColor Yellow
}

Write-Host "Creating Restore Point." -ForegroundColor Yellow
Try {
    Enable-ComputerRestore -Drive $env:SystemDrive -logErrorAction Stop
    Checkpoint-Computer -Description "BeforeDebloat" -RestorePointType "MODIFY_SETTINGS" -logErrorAction Stop
}
Catch {
    if (! $force) {
        Write-Host "Failed to create Restore Point, got: $_" -ForegroundColor Red
        Pause
        Exit
    } else {
        Write-Host "Failed to create Restore Point, proceed anyway."-ForegroundColor Yellow
    }
}
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
    Set-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name NoAutoUpdate -Value 1
}
function disableMedic {
    # disable medic
    Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\WaaSMedicSvc" -Name Start -Value 4

    # Take ownership and modifies discretionary access control lists 
    # HINT: this will work for 'en' but not for other languages, because group names are localized :/
    takeown /F C:\Windows\System32\Tasks\Microsoft\Windows\WaaSMedic /A /R
    icacls C:\Windows\System32\Tasks\Microsoft\Windows\WaaSMedic /grant Administrators:F /T

    Get-ScheduledTask -TaskPath "\Microsoft\Windows\WaaSMedic\" | Disable-ScheduledTask

    # delete the trigger for medic service
    $service = New-Object -ComObject Schedule.Service
    $service.Connect($env:COMPUTERNAME)

    $folder = $service.GetFolder('\Microsoft\Windows\WaaSMedic')

    $task = $folder.GetTask("PerformRemediation")
    $task.Definition.Triggers.Remove(1)

    $folder.RegisterTaskDefinition($task.Name, $task.Definition, 4, $null, $null, $null)
}
function disableOrchestrator {        
    # Take ownership and modifies discretionary access control lists 
    # HINT: this will work for 'en' but not for other languages, because group names are localized :/
    takeown /F C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator /A /R
    icacls C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator /grant Administrators:F /T

    Get-ScheduledTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" | Disable-ScheduledTask
}
function scheduleDisableWindowsUpdate {
    # scheduled task to disable Windows Update in case it somehow re-activates itself
    $repeat = (New-TimeSpan -Hours 8)
    $duration = (New-TimeSpan -Days 365)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat -RepetitionDuration $duration
    $arg = "Stop-Service -Name wuauserv;Set-Service -Name wuauserv -StartupType Disabled"
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
    Register-ScheduledTask DisableWindowsUpdate -Principal $principal -Action $action -Trigger $trigger
    # scheduled task to stop Medic Service in case it somehow re-activates itself
    $repeat1 = (New-TimeSpan -Hours 8)
    $duration1 = (New-TimeSpan -Days 365)
    $trigger1 = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval $repeat1 -RepetitionDuration $duration1
    $arg1 = "Stop-Service -Name WaaSMedicSvc;Set-Service -Name WaaSMedicSvc -StartupType Disabled"
    $principal1 = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $action1 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg1
    Register-ScheduledTask DisableWindowsUpdateMedic -Principal $principal1 -Action $action1 -Trigger $trigger1
}

$services = @("wuauserv", "WaaSMedicSvc", "UsoSvc") 
$services | ForEach-Object{
    Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
    Stop-Service -Name $_ -ErrorAction SilentlyContinue | Out-Null
}
Stop-Process -Name "MoUsoCoreWorker" -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
Stop-Process -Name "TiWorker" -Force -PassThru -ErrorAction SilentlyContinue | Out-Null
# Set various properties
disableWindowsUpdateServices
disableMedicService
disableOrchestrator
# schedule additional tasks
scheduleDisableWindowsUpdate