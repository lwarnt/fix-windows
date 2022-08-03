# Create Windows 11 installation medium

Create Windows 11 .iso for installation on 

* BIOS
* Without Secure Boot
* Without TPM

by placing the Windows image inside the Windows 10 installer.

**Requirements:**

* Windows 10 .iso
* Windows 11 .iso
* `genisoimage` or equivalent
* Disk space (~ 12GB)

> Probably Linux, I used on WSL (Debian) but you don't have to

## Usage

```bash
./make-iso.sh <Windows-10.iso> <Windows-11.iso>
```

> **Note** Does not guard against switching inputs. So make sure they are correct.