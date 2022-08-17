# Debloat Windows 11

> **Note** 
> 
> It will also change some settings that have little to do with bloat(ware). 

## Quickstart

```Powershell
start powershell -verb runas
```

Then

```Powershell
Set-ExecutionPolicy Unrestricted -Scope Process -Force -Confirm:$false
iwr https://raw.githubusercontent.com/lwarnt/fix-windows/main/debloat-windows11/debloat.ps1 | iex
```

## Usage

```Powershell
# unattended run (do not prompt), attempt restore point creation
.\debloat.ps1 $true
# prompt, skip restore point 
.\debloat.ps1 $false $true
# unattended run, create restore point but ignore restore point creation failure
.\debloat.ps1 $true $false $true
```
