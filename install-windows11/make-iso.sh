#!/bin/bash
NOCOLOR='\e[0m'
YELLOW='\e[33m'
RED='\e[31m'
INFO="[INFO]: "
ERROR="[ERROR]: "

# crude input validation
if [[ "$1" =~ ^/ ]] && [[ "$2" =~ ^/ ]]; then
    :
else 
    printf "Usage: ./make-iso.sh /path/to/Windows10.iso /path/to/Windows11.iso \n"
    printf "${RED}${ERROR}Paths must be absolute.\n${NOCOLOR}"
    exit 1
fi

W10_MOUNT="/mnt/win10"
W10_WORKDIR="/tmp/win10-unpacked"
W11_MOUNT="/mnt/win11"

printf "${YELLOW}${INFO}Create directories.\n${NOCOLOR}"
DIRS=( "$W10_MOUNT" "$W10_WORKDIR" "$W11_MOUNT" )
for dir in ${DIRS[@]}; do
    mkdir -p $dir
done

printf "${YELLOW}${INFO}Mount disk images.\n${NOCOLOR}"
mount -o loop "$1" "$W10_MOUNT"
mount -o loop "$2" "$W11_MOUNT"

printf "${YELLOW}${INFO}Copy files to working directory.\n${NOCOLOR}"
cp -R "$W10_MOUNT"/* "$W10_WORKDIR"

printf "${YELLOW}${INFO}Copy Windows image file to working directory.\n${NOCOLOR}"
cp "$W11_MOUNT"/sources/install.wim "$W10_WORKDIR"/sources/

printf "${YELLOW}${INFO}Package the new disk image.\n${NOCOLOR}"
# Source: https://unix.stackexchange.com/questions/531012/how-to-modify-an-installation-iso-and-keep-it-bootable
# -b needs to be relative -.-
cd "$W10_WORKDIR"
genisoimage --allow-limited-size \
    -no-emul-boot \
    -b "boot/etfsboot.com" \
    -boot-load-seg 0 \
    -boot-load-size 8 \
    -eltorito-alt-boot \
    -no-emul-boot \
    -b "efi/microsoft/boot/efisys.bin" \
    -boot-load-size 1 \
    -iso-level 4 \
    -udf \
    -o ../Windows11-out.iso \
    .

printf "${YELLOW}${INFO}Cleanup.\n${NOCOLOR}"
umount "$W10_MOUNT"
umount "$W11_MOUNT"
rm -rf "$W10_MOUNT"
rm -rf "$W11_MOUNT"
rm -rf "$W10_WORKDIR"

printf "${YELLOW}${INFO}Result:\n${NOCOLOR}"
ls -d -lh "/tmp/"*.iso

exit 0