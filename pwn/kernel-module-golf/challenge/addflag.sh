#!/bin/sh

./decompress.sh
rm -f rootfs/root/flag.txt
cp flag.txt rootfs/root/flag.txt
chmod 400 rootfs/root/flag.txt
./compress.sh