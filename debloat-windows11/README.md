# Debloat Windows 11

# TESTING BRANCH

> **Warning** Stuff that is here is either currently testing or not working.

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
# silent, do not prompt
.\debloat.ps1 $true
# force, ignore restore point creation failure
.\debloat.ps1 $false $true
# both
.\debloat.ps1 $true $true
```
