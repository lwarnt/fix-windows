# Deactivate Windows Update

# TESTING BRANCH

> **Warning** Stuff that is here is either currently testing or not working.

Deactivate the Windows Update service and its derivatives Microsoft introduced to reactivate it.

This is used in a virtual environment.

## Quickstart

```Powershell
start powershell -verb runas
```

Then

```Powershell
Set-ExecutionPolicy Unrestricted -Scope Process -Force -Confirm:$false
iwr https://raw.githubusercontent.com/lwarnt/fix-windows/main/disable-windows-update/main.ps1 | iex
```

