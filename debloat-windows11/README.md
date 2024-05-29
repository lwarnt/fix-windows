# Debloat Windows 11

Try to remove or disable Windows bloat.

> **Warning** Do not use if you don't know what it means.

## Quickstart

```Powershell
start powershell -verb runas
```

Then

```Powershell
Set-ExecutionPolicy Unrestricted -Scope Process -Force -Confirm:$false
iwr https://raw.githubusercontent.com/lwarnt/fix-windows/main/debloat-windows11/debloat.ps1 | iex
```

## the response content cannot be parsed because the Internet Explorer engine is not available

```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
```