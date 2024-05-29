# Deactivate Windows Update

Try to deactivate the Windows Update service.

> **Warning** Do not use if you don't know what it means.

## Quickstart

```Powershell
start powershell -verb runas
```

Then

```Powershell
Set-ExecutionPolicy Unrestricted -Scope Process -Force -Confirm:$false
iwr https://raw.githubusercontent.com/lwarnt/fix-windows/main/disable-windows-update/main.ps1 | iex
```

## the response content cannot be parsed because the Internet Explorer engine is not available

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
```