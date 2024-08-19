#!/bin/bash

mkdir -p rootfs
cd rootfs
cp ../initramfs.cpio.gz .
gzip -d initramfs.cpio.gz
cpio -idm < ./initramfs.cpio
rm initramfs.cpio