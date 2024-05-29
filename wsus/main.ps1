<# 
.SYNOPSIS
    Use WSUS server.

.DESCRIPTION 
    Set Windows Update to use specified WSUS server.
 
.NOTES 
    Needs to run as administrator. 'deregister' will remove WSUS, but keep Windows Update disabled.
#>
New-Module -Name RegisterWSUS -Scriptblock {
    
    . {Invoke-WebRequest https://raw.githubusercontent.com/lwarnt/fix-windows/main/disclaimer.ps1 } | Invoke-Expression

    function register {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$false, Position=0)]
            [Alias("Server")]
            [String] $s = "http://wsus.domain.com",

            [Parameter(Mandatory=$false, Position=1)]
            [Alias("Port")]
            [Int] $p = 8530
        )

        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Type dword -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Type dword -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Type string -Value "${s}:${p}"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Type string -Value "${s}:${p}"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "UpdateServiceUrlAlternate" -Type string -Value "${s}:${p}"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "SetProxyBehaviorForUpdateDetection" -Type dword -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AcceptTrustedPublisherCerts" -Type dword -Value 0x00000001
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Type dword -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "DetectionFrequencyEnabled" -Type dword -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "DetectionFrequency" -Type dword -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type dword -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type dword -Value 0x00000002
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Type dword -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Type dword -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallEveryWeek" -Type dword -Value 0x00000001    

    }

    Export-ModuleMember -Function "register"
} | Out-Null

New-Module -Name DeregisterWSUS -Scriptblock {
    
    . {Invoke-WebRequest https://raw.githubusercontent.com/lwarnt/fix-windows/main/disclaimer.ps1 } | Invoke-Expression

    function deregister {
        [CmdletBinding()]param()
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess" -Type dword -Value 0x00000001
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations" -Type dword -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AcceptTrustedPublisherCerts" -Type dword -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer" -Type dword -Value 0x00000000
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type dword -Value 0x00000003
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer" -Force | Out-Null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "UpdateServiceUrlAlternate" -Force | Out-Null
    }

    Export-ModuleMember -Function "deregister"

} | Out-Null