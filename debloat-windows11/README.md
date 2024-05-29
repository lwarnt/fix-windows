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
