# Create Windows 11 installation medium

Create Windows 11 .iso for installation on 

* BIOS
* Without Secure Boot
* Without TPM

by placing the Windows image inside the Windows 10 installer.

**Requirements:**

* Windows 10 .iso file
* Windows 11 .iso file
* `genisoimage` or equivalent
* Disk space (~ 12GB)

> Probably Linux, I used on WSL (Debian) but you don't have to

## Usage

```bash
./make-iso.sh /path/to/Windows-10.iso /path/to/Windows-11.iso
```

The result will be `/tmp/Windows11-out.iso`.

> **Note** Does not guard against switching inputs.

## Tests

Tested using these combinations:

* [x] 10 Enterprise Eval & 11 Enterprise Eval
* [x] 10 Business Edition & 11 Multi-Edition ISO