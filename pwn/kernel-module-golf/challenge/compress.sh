#!/bin/sh

cd rootfs
find . -print0 | cpio --null -o --format=newc --owner=root | gzip -9 > ../initramfs.cpio.gz