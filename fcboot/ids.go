package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// span is a range of host ids from /etc/subuid or /etc/subgid.
type span struct{ start, count int }

// ids are the host ids the jail maps, as rootless Podman maps them: root of the jail's user namespace is the caller,
// ids from 1 are the caller's subordinate ids, and one more group id stands for the host's kvm group.
type ids struct {
	uid, gid       int
	subuid, subgid span
	kvm            int // the host's kvm group, mapped by the line "<user>:<kvm>:1" in /etc/subgid
}

// jailUID is the uid Firecracker runs as inside the jail; on the host it is subuid.start + jailUID - 1.
const jailUID = 1001

// kvmInside is the jail's id for the host's kvm group: just above the subordinate range.
func (i ids) kvmInside() int { return i.subgid.count + 1 }

// mapping is unshare's id mapping for the jail's user namespace.
func (i ids) mapping() []string {
	return []string{
		fmt.Sprintf("--map-users=0:%d:1", i.uid), fmt.Sprintf("--map-users=1:%d:%d", i.subuid.start, i.subuid.count),
		fmt.Sprintf("--map-groups=0:%d:1", i.gid), fmt.Sprintf("--map-groups=1:%d:%d", i.subgid.start, i.subgid.count),
		fmt.Sprintf("--map-groups=%d:%d:1", i.kvmInside(), i.kvm),
	}
}

// readIDs reads the caller's ids and checks the two one-time root steps of the recipe.
func readIDs() (ids, error) {
	me, err := user.Current()
	if err != nil {
		return ids{}, err
	}
	kvm, err := user.LookupGroup("kvm")
	if err != nil {
		return ids{}, fmt.Errorf("no kvm group: %w", err)
	}
	i := ids{uid: os.Getuid(), gid: os.Getgid()}
	if i.kvm, err = strconv.Atoi(kvm.Gid); err != nil {
		return ids{}, err
	}
	uids, err := spans("/etc/subuid", me)
	if err != nil {
		return ids{}, err
	}
	gids, err := spans("/etc/subgid", me)
	if err != nil {
		return ids{}, err
	}
	for _, s := range uids {
		if s.count > jailUID {
			i.subuid = s
			break
		}
	}
	kvmMapped := false
	for _, s := range gids {
		if s.count > jailUID && i.subgid.count == 0 {
			i.subgid = s
		}
		if s.start == i.kvm && s.count == 1 {
			kvmMapped = true
		}
	}
	switch {
	case i.subuid.count == 0:
		return ids{}, fmt.Errorf("/etc/subuid has no range of more than %d ids for %s", jailUID, me.Username)
	case i.subgid.count == 0:
		return ids{}, fmt.Errorf("/etc/subgid has no range of more than %d ids for %s", jailUID, me.Username)
	case !kvmMapped:
		return ids{}, fmt.Errorf("/etc/subgid has no line %s:%d:1 (the kvm group)", me.Username, i.kvm)
	}
	return i, nil
}

// spans reads the ranges of a subordinate id file that belong to the user, by name or by uid.
func spans(path string, me *user.User) ([]span, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var found []span
	lines := bufio.NewScanner(file)
	for lines.Scan() {
		f := strings.Split(strings.TrimSpace(lines.Text()), ":")
		if len(f) != 3 || (f[0] != me.Username && f[0] != me.Uid) {
			continue
		}
		start, err1 := strconv.Atoi(f[1])
		count, err2 := strconv.Atoi(f[2])
		if err1 == nil && err2 == nil {
			found = append(found, span{start, count})
		}
	}
	return found, lines.Err()
}
