#!/bin/sh

set -e

LINUX="$HOME/ctf/development/idekctf-24/golf/linux"
BZIMAGE="$LINUX/arch/x86/boot/bzImage"

rm attachments/{bzImage,initramfs.cpio.gz} || true
rm challenge/{bzImage,initramfs.cpio.gz} || true

cp "$BZIMAGE" attachments/bzImage
cp "$BZIMAGE" challenge/bzImage
cp "$BZIMAGE" healthcheck/bzImage

cd challenge \
    && rm -f rootfs/root/flag.txt \
    && cp ../attachments/module/load.ko rootfs/ \
    && ./compress.sh \
    && cp initramfs.cpio.gz ../attachments \
    && cd -

cd challenge \
    && ./addflag.sh \
    && cd -