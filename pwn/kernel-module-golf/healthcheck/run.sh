#!/bin/sh

file="$1"
args=""
if [ -z "$1" ]; then
    file="./exploit"
    args="-s"
fi

qemu-system-x86_64 \
    -m 64m \
    -cpu qemu64,+smep,+smap \
    -kernel ./bzImage \
    -initrd ./initramfs.cpio.gz \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "init=/init console=ttyS0 loglevel=0 oops=panic panic=-1" \
    -drive file="$file",format=raw \
    $args