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
iwr https://raw.githubusercontent.com/lwarnt/fix-windows/main/disable-windows-update/main.ps1 | iex
```

## Usage

```Powershell
# unattended run (do not prompt), attempt restore point creation
.\main.ps1 $true
# prompt, skip restore point 
.\main.ps1 $false $true
# unattended run, create restore point but ignore restore point creation failure
.\main.ps1 $true $false $true
```
