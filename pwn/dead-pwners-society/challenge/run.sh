#!/bin/sh

IMG=$(mktemp)
FLAG=$(mktemp)

cp /home/user/root.img $IMG && \
    cp /home/user/flag.txt $FLAG && \
    qemu-system-x86_64 \
        -kernel /home/user/bzImage \
        -cpu qemu64,+smep,+smap \
        -m 2G \
        -smp 2 \
        -drive file="$IMG",if=ide \
        -append "console=ttyS0 root=/dev/sda quiet loglevel=3 kaslr kpti=1" \
        -hdb "$FLAG" \
        -drive file="$1",format=raw \
        -monitor /dev/null \
        -nographic \
        -no-reboot

rm -rf $IMG
rm -rf $FLAG
