#!/bin/bash
NOCOLOR='\e[0m'
YELLOW='\e[33m'
RED='\e[31m'

# crude input validation
if [[ "$1" =~ ^/ ]] && [[ "$2" =~ ^/ ]]; then
    :
else 
    printf "${RED}Paths must be absolute.\n${NOCOLOR}"
    exit 1
fi

W10_MOUNT="/mnt/win10"
W10_WORKDIR="/tmp/win10-unpacked"
W11_MOUNT="/mnt/win11"

printf "${YELLOW}Create directories.\n${NOCOLOR}"
DIRS=( "$W10_MOUNT" "$W10_WORKDIR" "$W11_MOUNT" )
for dir in ${DIRS[@]}; do
    mkdir -p $dir
done

printf "${YELLOW}Mount disk images.\n${NOCOLOR}"
mount -o loop "$1" "$W10_MOUNT"
mount -o loop "$2" "$W11_MOUNT"

printf "${YELLOW}Copy files to working directory.\n${NOCOLOR}"
cp -R "$W10_MOUNT"/* "$W10_WORKDIR"

printf "${YELLOW}Copy Windows image file to working directory.\n${NOCOLOR}"
cp "$W11_MOUNT"/sources/install.wim "$W10_WORKDIR"/sources/

printf "${YELLOW}Package the new disk image.\n${NOCOLOR}"
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

printf "${YELLOW}Cleanup.\n${NOCOLOR}"
umount "$W10_MOUNT"
umount "$W11_MOUNT"
rm -rf "$W10_MOUNT"
rm -rf "$W11_MOUNT"
rm -rf "$W10_WORKDIR"

printf "${YELLOW}This is the result:\n${NOCOLOR}"
ls -d -lh "/tmp/"*.iso

exit 0