<# 
.SYNOPSIS
    Debloat Windows 11 installation.

.DESCRIPTION 
    Removes and changes a lot of apps and settings in a Windows 11 installation.
    Attempts to create a Restore Point for reverting back.
 
.NOTES 
    Needs to run as administrator.
#>

. {Invoke-WebRequest https://raw.githubusercontent.com/lwarnt/fix-windows/main/disclaimer.ps1 } | Invoke-Expression

$ErrorActionPreference = 'SilentlyContinue'

# https://github.com/teeotsa/windows-11-debloat/blob/new/src/main.ps1

Write-Host "Disable Telemetry." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

Write-Host "Disable Application suggestions." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0

If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

Write-Host "Disable Activity History." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

Write-Host "Disable Location Tracking." -ForegroundColor Yellow
If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
# 2nd
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")){
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableSensors" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableWindowsLocationProvider" -Type DWord -Value 1

Write-Host "Disable automatic Maps updates." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps")){
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" -Name "AutoDownloadAndUpdateMapData" -Type DWord -Value 0

Write-Host "Disable Feedback." -ForegroundColor Yellow
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

Write-Host "Disable Tailored Experiences." -ForegroundColor Yellow
If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
    New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

Write-Host "Disable Advertising ID." -ForegroundColor Yellow
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

Write-Host "Stop and disable Diagnostics Tracking Service." -ForegroundColor Yellow
Stop-Service "DiagTrack" -WarningAction SilentlyContinue
Set-Service "DiagTrack" -StartupType Disabled

Write-Host "Stop and disable WAP Push Service." -ForegroundColor Yellow
Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
Set-Service "dmwappushservice" -StartupType Disabled

Write-Host "Disable Storage Sense." -ForegroundColor Yellow
Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue

Write-Host "Stop and disable Superfetch service." -ForegroundColor Yellow
Stop-Service "SysMain" -WarningAction SilentlyContinue
Set-Service "SysMain" -StartupType Disabled

Write-Host "Show file operations details." -ForegroundColor Yellow
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

Write-Host "Hide Task View button." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

Write-Host "Hide People icon." -ForegroundColor Yellow
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

Write-Host "Change default Explorer view." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

Write-Host "Hide 3D Objects." -ForegroundColor Yellow
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

Write-Host "Disable News and Interests" -ForegroundColor Yellow
if (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")){
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2

If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1

if (!(Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer")){
    New-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"

if (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost")){
    New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 0

Write-Host "Disable Handwriting Reports." -ForegroundColor Yellow
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports")){
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" -Name "PreventHandwritingErrorReports" -Type DWord -Value 1

Write-Host "Disable GameDVR." -ForegroundColor Yellow
if (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")){
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0

$Services = @(
    "*xbox*" # Xbox Services
    "*Xbl*" # Xbox Services
    "XboxNetApiSvc" # Xbox Services
    "icssvc" # Mobile Hotspot
    "MixedRealityOpenXRSvc" # Mixed Reality
    "WMPNetworkSvc" # Windows Media Player Sharing
    "WerSvc" # Error Reporting
    "SysMain" # SuperFetch - Safe to disable if you have a SSD
    "SCPolicySvc" # Smart Card Removal Policy
    "ScDeviceEnum" # Smart Card Device Enumeration Service
    "SCardSvr" # Smart Card
    "RetailDemo" # Retail Demo Service
    "WpcMonSvc" # Parental Controls
    "SmsRouter" # Microsoft Windows SMS Router Service
    "cloudidsvc" # Microsoft Cloud Identity Service
    "wlidsvc" # Microsoft Account Sign-in Assistant
    "*diagnosticshub*" # Microsoft (R) Diagnostics Hub Standard Collector Service
    "MapsBroker" # Downloaded Maps Manager
    "TrkWks" # Distributed Link Tracking Client
    "WdiSystemHost" # Diagnostic System Host
    "WdiServiceHost" # Diagnostic Service Host
    "DPS" # Diagnostic Policy Service
    "diagsvc" # Diagnostic Execution Service
    "AppReadiness" # App Readiness
)

foreach ($Service in $Services) {
Get-Service -Name $Service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled
    if($Service.Status -match "Run"){
        Stop-Service -Name $Service -Force -ErrorAction SilentlyContinue | Out-Null
        Write-Host "Disable service: $($Service.DisplayName)" -ForegroundColor Yellow
    }
}

[Array] @(
    "\Microsoft\Windows\ApplicationData\CleanupTemporaryState"
    "\Microsoft\Windows\ApplicationData\DsSvcCleanup"
    "\Microsoft\Windows\AppxDeploymentClient\Pre-stagedappcleanup"
    "\Microsoft\Windows\Autochk\Proxy"
    "\Microsoft\Windows\BrokerInfrastructure\BgTaskRegistrationMaintenanceTask"
    "\Microsoft\Windows\capabilityaccessmanager\maintenancetasks"
    "\Microsoft\Windows\Chkdsk\ProactiveScan"
    "\Microsoft\Windows\Chkdsk\SyspartRepair"
    "\Microsoft\Windows\Clip\LicenseValidation"
    "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
    "\Microsoft\Windows\CustomerExperienceImprovementProgram\Consolidator"
    "\Microsoft\Windows\CustomerExperienceImprovementProgram\UsbCeip"
    "\Microsoft\Windows\Defrag\ScheduledDefrag"
    "\Microsoft\Windows\DeviceInformation\Device"
    "\Microsoft\Windows\DeviceInformation\DeviceUser"
    "\Microsoft\Windows\DeviceSetup\MetadataRefresh"
    "\Microsoft\Windows\ExploitGuard\ExploitGuardMDMpolicyRefresh"
    "\Microsoft\Windows\Feedback\Siuf\DmClient"
    "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
    "\Microsoft\Windows\FileHistory\FileHistory*"
    "\Microsoft\Windows\Location\Notifications"
    "\Microsoft\Windows\Location\WindowsActionDialog"
    "\Microsoft\Windows\Maps\MapsToastTask"
    "\Microsoft\Windows\Maps\MapsUpdateTask"
    "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents"
    "\Microsoft\Windows\MemoryDiagnostic\RunFullMemoryDiagnostic"
    "\Microsoft\Windows\MUI\LPRemove"
    "\Microsoft\Windows\Multimedia\SystemSoundsService"
    "\Microsoft\Windows\OfflineFiles\BackgroundSynchronization"
    "\Microsoft\Windows\OfflineFiles\LogonSynchronization"
    "\Microsoft\Windows\Printing\EduPrintProv"
    "\Microsoft\Windows\Printing\PrinterCleanupTask"
    "\Microsoft\Windows\PushToInstall\LoginCheck"
    "\Microsoft\Windows\PushToInstall\Registration"
    "\Microsoft\Windows\RetailDemo\CleanupOfflineContent"
    "\Microsoft\Windows\Servicing\StartComponentCleanup"
    "\Microsoft\Windows\Setup\SetupCleanupTask"
    "\Microsoft\Windows\SharedPC\AccountCleanup"
    "\Microsoft\Windows\UNP\RunUpdateNotificationMgr"
    "\Microsoft\Windows\WindowsErrorReporting\QueueReporting"
    "\Microsoft\XblGameSave\XblGameSaveTask"
) | ForEach-Object{
    Disable-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Disable task: $_" -ForegroundColor Yellow
}

Write-Host "Disable Bing Search." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1

Write-Host "Stop Windows Search indexing service." -ForegroundColor Yellow
Stop-Service "WSearch" -WarningAction SilentlyContinue
Set-Service "WSearch" -StartupType Disabled

Write-Host "Hide Taskbar Search icon." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

Write-Host "Disable Cortana." -ForegroundColor Yellow
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

Write-Host "Enable old context menu." -ForegroundColor Yellow
New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID" -Force | Out-Null
New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Force | Out-Null
New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force -Value "" | Out-Null

Write-Host "Disable visual fluff." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 200
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](144,18,3,128,16,0,0,0))
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0

Write-Host "Disable Toggle Keys and Sticky Keys." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "122"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58"

# https://github.com/teeotsa/windows-11-debloat/blob/new/src/main.ps1
# https://github.com/kdpuvvadi/debloat-windows11/blob/main/debloat.ps1

Write-Host "Remove OneDrive." -ForegroundColor Yellow
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
Stop-Process -Name *onedrive* -ErrorAction SilentlyContinue -Force
Start-Sleep -Seconds 2
$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
If (!(Test-Path $onedrive)) {
    $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
}
Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
Start-Sleep -Seconds 2
Stop-Process -Process $(Get-Process explorer) -Restart -RestartDelay 5
Start-Sleep -Seconds 2
If (!(Test-Path "HKCR:")) {
    New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
}
Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
    Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse | Out-Null
}
$OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
If (!(Test-Path $OneDriveKey)) { Mkdir $OneDriveKey | Out-Null }

# https://github.com/teeotsa/windows-11-debloat/blob/new/src/main.ps1
# https://github.com/kdpuvvadi/debloat-windows11/blob/main/debloat.ps1

Write-Host "Remove bloat." -ForegroundColor Yellow
$BloatwareList = @(
    "Microsoft.BingNews"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.OneNote"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.RemoteDesktop"
    "Microsoft.SkypeApp"
    "Microsoft.StorePurchaseApp"
    "Microsoft.Office.Todo.List"
    "Microsoft.Whiteboard"
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"

    #Sponsored Windows 11 AppX Apps
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "AdobeSystemsIncorporated.AdobePhotoshopExpress"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*BubbleWitch3Saga*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Spotify*"
    "*Minecraft*"
    "*Royal Revolt*"
    "*Sway*"
    "*Speed Test*"
    "*Dolby*"
)

foreach($Bloat in $BloatwareList){
    if((Get-AppxPackage -Name $Bloat).NonRemovable -eq $false) {
        Write-Host "Remove $Bloat" -ForegroundColor Yellow
        Try {
            Get-AppxPackage -Name $Bloat | Remove-AppxPackage -ErrorAction Stop | Out-Null
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online -ErrorAction Stop | Out-Null
        }
        Catch { logError("Remove $Bloat, exception : $($_)") }
    }  
}

# https://github.com/kdpuvvadi/debloat-windows11/blob/main/debloat.ps1
# Don't care about overlap, as long as the bloat is gone

Write-Host "Enable File Extensions." -ForegroundColor Yellow
$ExpPath = "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if (Test-Path $ExpPath) {
    Set-ItemProperty -Path $ExpPath -Name HideFileExt -Value 0
}

Write-Host "Disable Windows Feedback Experience program." -ForegroundColor Yellow
$Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
If (Test-Path $Advertising) {
    Set-ItemProperty $Advertising Enabled -Value 0 
}
$Period = "HKCU:\Software\Microsoft\Siuf\Rules"
If (!(Test-Path $Period)) { New-Item $Period | Out-Null }
Set-ItemProperty $Period PeriodInNanoSeconds -Value 0
        
Write-Host "Stop Cortana in Windows Search." -ForegroundColor Yellow
$Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
If (Test-Path $Search) {
    Set-ItemProperty $Search AllowCortana -Value 0 
}

Write-Host "Disable Bing Search." -ForegroundColor Yellow
$WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
If (!(Test-Path $WebSearch)) { New-Item $WebSearch | Out-Null }
Set-ItemProperty $WebSearch DisableWebSearch -Value 1

Write-Host "Prevent bloatware apps from returning." -ForegroundColor Yellow
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
If (!(Test-Path $registryPath)) { New-Item $registryPath | Out-Null }
Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 

If (!(Test-Path $registryOEM)) { New-Item $registryOEM | Out-Null }
Set-ItemProperty $registryOEM ContentDeliveryAllowed -Value 0 
Set-ItemProperty $registryOEM OemPreInstalledAppsEnabled -Value 0 
Set-ItemProperty $registryOEM PreInstalledAppsEnabled -Value 0 
Set-ItemProperty $registryOEM PreInstalledAppsEverEnabled -Value 0 
Set-ItemProperty $registryOEM SilentInstalledAppsEnabled -Value 0 
Set-ItemProperty $registryOEM SystemPaneSuggestionsEnabled -Value 0          

Write-Host "Allow uninstall of Mixed Reality Portal." -ForegroundColor Yellow
$Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
If (Test-Path $Holo) { Set-ItemProperty $Holo FirstRunSucceeded -Value 0 }

Write-Host "Disable Wi-Fi Sense." -ForegroundColor Yellow
$WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
$WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
$WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
If (!(Test-Path $WifiSense1)) { New-Item $WifiSense1 | Out-Null }
Set-ItemProperty $WifiSense1  Value -Value 0 
If (!(Test-Path $WifiSense2)) { New-Item $WifiSense2 | Out-Null }
Set-ItemProperty $WifiSense2 Value -Value 0 
Set-ItemProperty $WifiSense3 AutoConnectAllowedOEM -Value 0 
    
Write-Host "Disable live tiles." -ForegroundColor Yellow
$Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
If (!(Test-Path $Live)) { New-Item $Live | Out-Null }
Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 
    
Write-Host "Turn off Data Collection." -ForegroundColor Yellow
$DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
$DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
If (Test-Path $DataCollection1) {
    Set-ItemProperty $DataCollection1 AllowTelemetry -Value 0 
}
If (Test-Path $DataCollection2) {
    Set-ItemProperty $DataCollection2 AllowTelemetry -Value 0 
}
If (Test-Path $DataCollection3) {
    Set-ItemProperty $DataCollection3 AllowTelemetry -Value 0 
}

Write-Host "Disable Location Tracking." -ForegroundColor Yellow
$SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
$LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
If (!(Test-Path $SensorState)) { New-Item $SensorState | Out-Null }
Set-ItemProperty $SensorState SensorPermissionState -Value 0 
If (!(Test-Path $LocationConfig)) { New-Item $LocationConfig | Out-Null }
Set-ItemProperty $LocationConfig Status -Value 0

Write-Host "Remove CloudStore." -ForegroundColor Yellow
$CloudStore = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore'
If (Test-Path $CloudStore) {
    Stop-Process $(Get-Process explorer) -Force | Out-Null
    Remove-Item $CloudStore -Recurse -Force
}

Write-Host "Set Start Menu left." -ForegroundColor Yellow
$explorerPath = "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
if(Test-Path $explorerPath) {
    Set-ItemProperty -Path $explorerPath -Name TaskbarAl -Value 0
}

Write-Host "Remove Widget button." -ForegroundColor Yellow
if(Test-Path $explorerPath) {
    Set-ItemProperty -Path $explorerPath -Name TaskbarDa -Value 0
}

[Array] @(
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"

    "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        
    "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
    "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
    "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
) | ForEach-Object{
    Write-Host "Remove $_" -ForegroundColor Yellow
    Remove-Item $_ -Recurse | Out-Null
}

Write-Host "Remove 3D Objects context menu entry." -ForegroundColor Yellow
$Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
$Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
If (Test-Path $Objects32) {
    Remove-Item $Objects32 -Recurse | Out-Null
}
If (Test-Path $Objects64) {
    Remove-Item $Objects64 -Recurse | Out-Null
}

Write-Host "Restart explorer a final time." -ForegroundColor Yellow
Stop-Process $(Get-Process explorer) -Force | Out-Null
Start-Process explorer.exe -Wait | Out-Null