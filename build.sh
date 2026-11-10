#!/bin/sh
# Builds fcboot and the guest's /init, both static, and a 16 MiB ext4 root image that holds only /init. Needs Go and
# e2fsprogs; no root.
set -eu
cd "$(dirname "$0")"
rm -rf build
mkdir -p build/rootfs/dev build/rootfs/proc
CGO_ENABLED=0 go build -trimpath -o build/fcboot ./fcboot # static: "fcboot drop" runs inside the jail
CGO_ENABLED=0 go build -trimpath -o build/rootfs/init ./guest
mkfs.ext4 -q -F -d build/rootfs build/rootfs.ext4 16M
ls -l build/fcboot build/rootfs.ext4
