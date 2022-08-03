# Deactivate Windows Update

Deactivate the Windows Update service and its derivatives Microsoft introduced to reactivate it.

This is used in a virtual environment.

## Quickstart

```Powershell
start powershell -verb runas
```

Then

```Powershell
Set-ExecutionPolicy Unrestricted -Scope Process -Force -Confirm:$false
iwr https://raw.githubusercontent.com/lwarnt/fix-windows/deactivate-windows-update/main/main.ps1 | iex
```

