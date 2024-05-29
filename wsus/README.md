# Windows Server Update Services

Set Windows Update to use WSUS.

> **Warning** Do not use if you don't know what it means.

## Quickstart

```Powershell
. { iwr https://raw.githubusercontent.com/lwarnt/fix-windows/main/wsus/main.ps1 } | iex; register -Server https://wsus.mydomain.com -Port 8531
. { iwr https://raw.githubusercontent.com/lwarnt/fix-windows/main/wsus/main.ps1 } | iex; deregister
```

## the response content cannot be parsed because the Internet Explorer engine is not available

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
```