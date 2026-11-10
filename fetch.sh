#!/bin/sh
# Downloads Firecracker v1.18.0 and a guest kernel from Firecracker's CI into dl/, each checked against a pinned SHA-256.
# Firecracker publishes SHA-256 sums but no signatures (firecracker#6117): the sums check the transfer, not the origin.
set -eu
cd "$(dirname "$0")"
mkdir -p dl
cd dl

release=https://github.com/firecracker-microvm/firecracker/releases/download/v1.18.0
tarball=firecracker-v1.18.0-x86_64.tgz
curl --fail --silent --show-error --location --max-time 300 -o "$tarball" "$release/$tarball"
echo "1ac8eec866dd5eea14efecf6323e22b23eea24054545338a5b34bc5bca6623cd  $tarball" | sha256sum --check
entry=release-v1.18.0-x86_64/firecracker-v1.18.0-x86_64
tar -xzf "$tarball" "$entry"
echo "b33f46cd6d88834cf6a4f8d184f08f219809c636236bffd286d233a60602a2ba  $entry" | sha256sum --check
mv "$entry" firecracker
rm -r release-v1.18.0-x86_64

# The newest kernel of Firecracker's CI on 2026-11-10, as its getting-started guide finds it; Firecracker says these
# kernels are not meant for production. The hash is the one we downloaded; the bucket publishes none.
kernel=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20261105-6ea6634994fa-0/x86_64/vmlinux-6.18.56
curl --fail --silent --show-error --max-time 300 -o vmlinux "$kernel"
echo "af348226aa2a25b846156150d5cdb5dae3bf2a022f1db176e3a2b9a3249817bf  vmlinux" | sha256sum --check
ls -l firecracker vmlinux
