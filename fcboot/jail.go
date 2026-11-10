package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// jailArgs returns the call that jails Firecracker, as rootless Podman would: unshare makes a user namespace whose root is
// the caller and whose further ids are the caller's subordinate ids; bubblewrap runs there as that root, so it can bind the
// caller's files, with only the capabilities to change owners and ids; inside, "fcboot drop" hands /vm over, takes the
// jail's uid with the kvm group as its only group, and execs Firecracker, which then has no capability and no access to
// the caller's files, but can open /dev/kvm.
//
// The jail has every namespace, no nested user namespaces (Firecracker's own seccomp filters allow neither unshare,
// clone, clone3 nor setns), a cleared environment and a read-only root that holds only Firecracker, the kernel, the root
// image, the configuration, /dev/kvm and the VM's socket directory /vm, its one writable place.
func jailArgs(o options, i ids, config, socketDir, unit string) []string {
	self, _ := os.Executable()
	args := append([]string{"/usr/bin/unshare"}, i.mapping()...)
	return append(args, "--", o.bwrap,
		"--cap-drop", "ALL", "--cap-add", "CAP_SETUID", "--cap-add", "CAP_SETGID", "--cap-add", "CAP_CHOWN",
		"--unshare-pid", "--unshare-net", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup", "--hostname", "fc",
		"--die-with-parent", "--new-session", "--clearenv",
		"--dev", "/dev", "--dev-bind", "/dev/kvm", "/dev/kvm", "--proc", "/proc",
		"--perms", "0755", "--dir", "/fc", // bwrap would make it 0700, closed to the jail's uid
		"--ro-bind", o.firecracker, "/fc/firecracker",
		"--ro-bind", o.kernel, "/fc/vmlinux",
		"--ro-bind", o.rootfs, "/fc/rootfs.ext4",
		"--ro-bind", config, "/fc/vm.json",
		"--ro-bind", self, "/fc/fcboot",
		"--bind", socketDir, "/vm",
		"--remount-ro", "/", "--",
		"/fc/fcboot", "drop", strconv.Itoa(jailUID), strconv.Itoa(i.kvmInside()),
		"/fc/firecracker", "--no-api", "--config-file", "/fc/vm.json", "--id", unit)
}

// drop runs inside the jail: uid, gid, then the command. It hands /vm to the jail's uid, takes that uid with gid as its
// only group, which removes every capability, and execs the command.
func drop(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "drop: uid, gid and command needed")
		return 2
	}
	uid, err1 := strconv.Atoi(args[0])
	gid, err2 := strconv.Atoi(args[1])
	if err1 != nil || err2 != nil {
		fmt.Fprintln(os.Stderr, "drop: uid and gid must be numbers")
		return 2
	}
	// The entries first: once /vm is the jail's, its 0700 keeps out even this root, which has no CAP_DAC_OVERRIDE.
	entries, _ := os.ReadDir("/vm")
	var paths []string
	for _, entry := range entries {
		paths = append(paths, "/vm/"+entry.Name())
	}
	for _, path := range append(paths, "/vm") {
		if err := os.Lchown(path, uid, gid); err != nil {
			fmt.Fprintln(os.Stderr, "drop: hand over /vm:", err)
			return 3
		}
	}
	if err := syscall.Setgroups(nil); err != nil {
		fmt.Fprintln(os.Stderr, "drop: setgroups:", err)
		return 3
	}
	if err := syscall.Setgid(gid); err != nil {
		fmt.Fprintln(os.Stderr, "drop: setgid:", err)
		return 3
	}
	if err := syscall.Setuid(uid); err != nil {
		fmt.Fprintln(os.Stderr, "drop: setuid:", err)
		return 3
	}
	err := syscall.Exec(args[2], args[2:], []string{"PWD=/"})
	fmt.Fprintln(os.Stderr, "drop: exec:", err)
	return 3
}

// removeAsJailRoot removes a directory that holds files of the jail's uid, which the caller cannot delete: as root of a
// user namespace with the jail's mapping, as "podman unshare" does.
func removeAsJailRoot(i ids, dir string) error {
	if _, err := os.Lstat(dir); err != nil {
		return nil
	}
	args := append(i.mapping(), "--", "/usr/bin/rm", "-rf", "--", dir)
	return exec.Command("/usr/bin/unshare", args...).Run()
}

// check is one measure of the jail, read from the host while Firecracker runs.
type check struct {
	name, got string
	ok        bool
}

// inspect reads the jailed Firecracker process of unit's scope from the host.
func inspect(o options, i ids, unit string) []check {
	pid, err := firecrackerPID(unit)
	if err != nil {
		return []check{{"Firecracker process found", err.Error(), false}}
	}
	proc := "/proc/" + strconv.Itoa(pid)
	var checks []check
	for _, ns := range []string{"user", "mnt", "pid", "net", "ipc", "uts", "cgroup"} {
		own, _ := os.Readlink("/proc/self/ns/" + ns)
		its, err := os.Readlink(proc + "/ns/" + ns)
		checks = append(checks, check{"own " + ns + " namespace", its, err == nil && its != own})
	}
	status := fields(proc + "/status")
	jailHostUID := strconv.Itoa(i.subuid.start + jailUID - 1)
	checks = append(checks,
		check{"no new privileges", status["NoNewPrivs"], status["NoNewPrivs"] == "1"},
		check{"no effective capabilities", status["CapEff"], status["CapEff"] == "0000000000000000"},
		check{"a subordinate uid, not the caller's", status["Uid"], strings.HasPrefix(status["Uid"], jailHostUID+" ")},
		check{"kvm is its only group", status["Gid"] + "; " + status["Groups"],
			strings.HasPrefix(status["Gid"], strconv.Itoa(i.kvm)+" ") && status["Groups"] == ""},
		seccompCheck(proc),
	)
	env, err := inJail(pid, "/usr/bin/cat", proc+"/environ")
	// bwrap sets PWD after --clearenv; drop passes only that.
	checks = append(checks, check{"environment only PWD=/", strings.ReplaceAll(string(env), "\x00", " "),
		err == nil && string(env) == "PWD=/\x00"})
	checks = append(checks, rootCheck(proc), readOnlyCheck(proc), fdCheck(pid, proc), netCheck(proc),
		callerFileCheck(o, i))
	return checks
}

// inJail runs a command as root of the jail's user namespace, which the caller owns and so may enter: a process of the
// subordinate uid keeps its environment and descriptors from the caller's uid.
func inJail(pid int, command ...string) ([]byte, error) {
	args := append([]string{"--user", "--target", strconv.Itoa(pid), "--"}, command...)
	return exec.Command("/usr/bin/nsenter", args...).Output()
}

// callerFileCheck makes a file only the caller may read and tries to read it as the jail's host uid.
func callerFileCheck(o options, i ids) check {
	file, err := os.CreateTemp(o.runs, "caller-*")
	if err != nil {
		return check{"no access to the caller's files", err.Error(), false}
	}
	defer os.Remove(file.Name())
	file.WriteString("the caller's\n")
	file.Close()
	os.Chmod(o.runs, 0o755) // the directory must be passable, so that only the file's own mode decides
	out, err := exec.Command("/usr/bin/unshare",
		fmt.Sprintf("--map-users=0:%d:%d", i.subuid.start, i.subuid.count),
		fmt.Sprintf("--map-groups=0:%d:%d", i.subgid.start, i.subgid.count),
		"--setuid", strconv.Itoa(jailUID-1), "--setgid", strconv.Itoa(jailUID-1),
		"--", "/usr/bin/cat", file.Name()).CombinedOutput()
	return check{"no access to the caller's files", strings.TrimSpace(string(out)), err != nil}
}

// firecrackerPID finds the Firecracker process among the processes of unit's scope.
func firecrackerPID(unit string) (int, error) {
	out, err := exec.Command("systemctl", "--user", "show", "-p", "ControlGroup", "--value", unit+".scope").Output()
	if err != nil {
		return 0, fmt.Errorf("control group of %s: %w", unit, err)
	}
	procs, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", strings.TrimSpace(string(out)), "cgroup.procs"))
	if err != nil {
		return 0, err
	}
	for _, field := range strings.Fields(string(procs)) {
		if exe, err := os.Readlink("/proc/" + field + "/exe"); err == nil && filepath.Base(exe) == "firecracker" {
			return strconv.Atoi(field)
		}
	}
	return 0, fmt.Errorf("no firecracker among %q", strings.Fields(string(procs)))
}

// fields reads a /proc status file as name and value.
func fields(path string) map[string]string {
	m := make(map[string]string)
	data, _ := os.ReadFile(path)
	for line := range strings.Lines(string(data)) {
		if name, value, ok := strings.Cut(line, ":"); ok {
			m[name] = strings.Join(strings.Fields(value), " ")
		}
	}
	return m
}

func seccompCheck(proc string) check {
	tasks, _ := os.ReadDir(proc + "/task")
	filtered := 0
	for _, task := range tasks {
		if fields(proc + "/task/" + task.Name() + "/status")["Seccomp"] == "2" {
			filtered++
		}
	}
	return check{"seccomp filter on every thread", fmt.Sprintf("%d of %d threads", filtered, len(tasks)),
		len(tasks) > 0 && filtered == len(tasks)}
}

func rootCheck(proc string) check {
	entries, err := os.ReadDir(proc + "/root")
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	allowed := []string{"dev", "fc", "proc", "vm"}
	ok := err == nil && !slices.ContainsFunc(names, func(name string) bool { return !slices.Contains(allowed, name) })
	return check{"root holds only dev, fc, proc, vm", strings.Join(names, " "), ok}
}

// readOnlyCheck reads the jail's mount table: the root and everything under /fc must be read-only.
func readOnlyCheck(proc string) check {
	data, err := os.ReadFile(proc + "/mountinfo")
	var writable []string
	for line := range strings.Lines(string(data)) {
		f := strings.Fields(line) // mount id, parent, device, root, mount point, options, ...
		if len(f) < 6 {
			continue
		}
		point, options := f[4], strings.Split(f[5], ",")
		if (point == "/" || strings.HasPrefix(point, "/fc")) && !slices.Contains(options, "ro") {
			writable = append(writable, point)
		}
	}
	return check{"root and /fc read-only", "writable: " + strings.Join(writable, " "), err == nil && len(writable) == 0}
}

func fdCheck(pid int, proc string) check {
	listing, err := inJail(pid, "/usr/bin/find", proc+"/fd", "-mindepth", "1", "-maxdepth", "1", "-printf", "%l\n")
	targets := strings.Fields(string(listing))
	var paths []string
	for _, target := range targets {
		if strings.HasPrefix(target, "/") {
			paths = append(paths, target)
		}
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	ok := err == nil && len(targets) > 0 && !slices.ContainsFunc(paths, func(path string) bool {
		return !strings.HasPrefix(path, "/fc/") && !strings.HasPrefix(path, "/vm/") && !strings.HasPrefix(path, "/dev/")
	})
	return check{"descriptors only on jail paths", fmt.Sprintf("%d open; files %s", len(targets), strings.Join(paths, " ")), ok}
}

func netCheck(proc string) check {
	data, err := os.ReadFile(proc + "/net/dev")
	var names []string
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if name, _, ok := strings.Cut(line, ":"); ok && i >= 2 {
			names = append(names, strings.TrimSpace(name))
		}
	}
	return check{"network: loopback only", strings.Join(names, " "), err == nil && slices.Equal(names, []string{"lo"})}
}
