# Firecracker on WSL2, without root

Reference code for the article "Firecracker on WSL2, without root" on [mko.run](https://mko.run). It boots a minimal
[Firecracker](https://github.com/firecracker-microvm/firecracker) microVM nested in WSL2, with no root at run time:

- in a systemd user scope of its own slice, whose memory, swap, task and CPU limits a guard reads back from the scope's
  cgroup before anything starts (`systemd-run` does not fail when a limit is not applied);
- in a [bubblewrap](https://github.com/containers/bubblewrap) jail with every namespace, no capability, a cleared
  environment and a read-only root that holds only `/dev` (with `/dev/kvm`), `/proc`, `/fc` (Firecracker, kernel, root
  image, configuration and `fcboot`, which drops to the jail's uid) and the VM's socket directory `/vm`, its one
  writable place;
- under a subordinate uid, as rootless Podman runs containers, with `kvm` as its only group;
- with no network interface: the guest's only channel is vsock.

While the first VM runs, `fcboot` reads the jailed Firecracker process from the host and checks each of these.

It is a reference for the article, not maintained, and not a sandbox to rely on: Firecracker does not support or test
WSL2, its supported way to confine itself is the [jailer](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md),
which needs root, and nothing here has been attacked. Questions, findings, or a request for the boundary tests the
article describes are welcome as an issue all the same.

Tested on 2026-11-10: WSL2 kernel 6.18.33.2, Debian 13.5, systemd 257.13, bubblewrap 0.11.0, uidmap 4.17.4,
util-linux 2.41, Firecracker v1.18.0, guest kernel 6.18.56 from Firecracker's CI, Go 1.27.3; Intel i7-12700H.

## Once, as root

1. Put yourself in the `kvm` group, then log in again (in WSL: `wsl --shutdown` from Windows, then start it):

   ```sh
   sudo usermod -aG kvm "$USER"
   ```

   Not `setfacl` on `/dev/kvm`, as Firecracker's getting-started guide also suggests: where udev tags `kvm` with
   `uaccess` and there is no seat user, as in WSL, udev rewrites the device's ACL each time a VM is created, and the
   entry is gone after the first VM.

2. Let your user namespaces map the `kvm` group:

   ```sh
   echo "$USER:$(getent group kvm | cut -d: -f3):1" | sudo tee -a /etc/subgid
   ```

   You also need ranges of subordinate ids in `/etc/subuid` and `/etc/subgid`
   (`grep "^$USER:" /etc/subuid /etc/subgid`); `useradd` adds them where `/etc/login.defs` sets `SUB_UID_COUNT`, as
   Debian's does.

3. Install what the recipe calls: `sudo apt install bubblewrap uidmap e2fsprogs curl`, and Go 1.26 or newer.

WSL must run systemd (`[boot] systemd=true` in `/etc/wsl.conf`), and `/dev/kvm` must exist (nested virtualization).

## Run

```sh
./fetch.sh       # Firecracker v1.18.0 and a CI guest kernel into dl/, each checked against a pinned SHA-256
./build.sh       # fcboot, the guest's /init and a 16 MiB root image into build/
./build/fcboot check
./build/fcboot -n 20 -firecracker dl/firecracker -kernel dl/vmlinux -rootfs build/rootfs.ext4 -runs runs
./build/fcboot clean runs   # runs/ holds files of the subordinate uid, which your own uid cannot remove
```

Each VM has 1 vCPU and 128 MiB, in a scope of at most 256 MiB, no swap, 64 tasks and one CPU. The guest's `/init`
reports `ready` over vsock and waits for the host's answer before it ends the VM: a guest that ends right after its
write can lose the line. `-jail=false` runs Firecracker in the scope without the jail, for comparison.

```
limits in force in /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/fcboot.slice/fcboot-check-985829.scope: memory 256 MiB, no swap, 64 tasks, one CPU
run  ready    ended    peak     outcome
  1    172 ms   227 ms  55.6 MiB ok
     true  own user namespace                     user:[4026532222]
     true  own mnt namespace                      mnt:[4026532225]
     true  own pid namespace                      pid:[4026532228]
     true  own net namespace                      net:[4026532230]
     true  own ipc namespace                      ipc:[4026532227]
     true  own uts namespace                      uts:[4026532226]
     true  own cgroup namespace                   cgroup:[4026532229]
     true  no new privileges                      1
     true  no effective capabilities              0000000000000000
     true  a subordinate uid, not the caller's    101000 101000 101000 101000
     true  kvm is its only group                  992 992 992 992;
     true  seccomp filter on every thread         3 of 3 threads
     true  environment only PWD=/                 PWD=/
     true  root holds only dev, fc, proc, vm      dev fc proc vm
     true  root and /fc read-only                 writable:
     true  descriptors only on jail paths         30 open; files /dev/kvm /dev/null /fc/rootfs.ext4
     true  network: loopback only                 lo
     true  no access to the caller's files        cat: runs/caller-901120372: Permission denied
```

`ready` counts from the start of `systemd-run` to the guest's line over vsock. On the machine above, twenty boots took
172 to 213 ms (median 191.5 ms) and peaked at 55 to 58 MiB per scope.

The boot arguments repeat `i8042.noaux i8042.nomux i8042.dumbkbd` from Firecracker's default command line, which any
`boot_args` replace whole. Without them, the CI kernel, which has the AT keyboard driver, probes a keyboard that is not
there for about half a second: twenty boots without them took 643 to 692 ms.

## How the jail is built

`unshare` makes a user namespace whose root is you and whose ids from 1 are your subordinate ids; one more group id
stands for the host's `kvm` group. `bwrap` runs there as that root, so it can bind your files, keeping only
`CAP_SETUID`, `CAP_SETGID` and `CAP_CHOWN`. Inside, `fcboot drop` hands the socket directory `/vm` to the jail's uid,
takes that uid with `kvm` as its only group, which drops every capability, and execs Firecracker. Firecracker's own
seccomp filters allow neither `unshare`, `clone`, `clone3` nor `setns`, so the jail needs no rule of its own against
nested namespaces. bwrap creates bind targets with mode 0700, so `/fc` is made 0755 for the jail's uid.

The host reads the jailed process's environment and descriptors as root of the jail's user namespace (`nsenter
--user`): a process of the subordinate uid keeps them from your own uid.

## License

MIT, see [LICENSE](LICENSE).
