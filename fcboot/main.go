// Command fcboot boots a minimal Firecracker microVM several times in a row, one at a time, without root: each VM runs
// in a systemd user scope of its own slice, whose limits a guard checks before anything starts, and, unless -jail=false,
// in a bubblewrap jail under a subordinate uid. It measures the time until the guest reports over vsock and the scope's
// peak memory, and reads the jail's measures from the host while the first VM runs.
//
//	fcboot check            only checks that the scope's limits are in force; starts no VM
//	fcboot -n 20 ...        boots twenty VMs, one after the other
//	fcboot clean DIR        removes a runs directory, which holds files of the jail's uid
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	guestMiB = 128
	scopeMiB = 256 // guest memory plus Firecracker and the guard
	tasks    = 64
	cpuMax   = "100000 100000" // CPUQuota=100%: one vCPU's worth, VMM thread included
	timeout  = 30 * time.Second
	killWait = 5 * time.Second
	logBytes = 1 << 20 // Firecracker's stdout carries the guest's serial output, so it is bounded
	slice    = "fcboot.slice"
)

type options struct {
	firecracker, kernel, rootfs, runs, bwrap string
	jail                                     bool
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "guard":
			os.Exit(guard(os.Args[2:]))
		case "drop":
			os.Exit(drop(os.Args[2:]))
		case "check":
			os.Exit(checkLimits())
		case "clean":
			os.Exit(clean(os.Args[2:]))
		}
	}
	var o options
	n := flag.Int("n", 20, "number of boots")
	flag.StringVar(&o.firecracker, "firecracker", "", "path of the firecracker binary")
	flag.StringVar(&o.kernel, "kernel", "", "path of the guest kernel (vmlinux)")
	flag.StringVar(&o.rootfs, "rootfs", "", "path of the guest root image (ext4, mounted read-only)")
	flag.StringVar(&o.runs, "runs", "", "directory for the runs' configurations, logs and results")
	flag.StringVar(&o.bwrap, "bwrap", "/usr/bin/bwrap", "path of bwrap")
	flag.BoolVar(&o.jail, "jail", true, "run Firecracker in the bubblewrap jail under a subordinate uid")
	flag.Parse()
	if o.firecracker == "" || o.kernel == "" || o.rootfs == "" || o.runs == "" {
		fmt.Fprintln(os.Stderr, "fcboot: -firecracker, -kernel, -rootfs and -runs are required")
		os.Exit(2)
	}
	if code := checkLimits(); code != 0 {
		os.Exit(code)
	}
	if err := boots(*n, o); err != nil {
		fmt.Fprintln(os.Stderr, "fcboot:", err)
		os.Exit(1)
	}
}

// clean removes runs directories as root of the jail's user namespace.
func clean(dirs []string) int {
	i, err := readIDs()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fcboot:", err)
		return 1
	}
	for _, dir := range dirs {
		if err := removeAsJailRoot(i, dir); err != nil {
			fmt.Fprintln(os.Stderr, "fcboot: remove", dir+":", err)
			return 1
		}
	}
	return 0
}

// scope returns the systemd-run call that runs command in a scope of fcboot's own slice, with its limits.
func scope(unit string, command ...string) *exec.Cmd {
	args := []string{"--user", "--scope", "--quiet", "--slice=" + slice, "--unit=" + unit,
		"-p", "MemoryMax=" + strconv.Itoa(scopeMiB) + "M", "-p", "MemorySwapMax=0",
		"-p", "TasksMax=" + strconv.Itoa(tasks), "-p", "CPUQuota=100%"}
	return exec.Command("systemd-run", append(append(args, "--"), command...)...)
}

// checkLimits starts the guard alone in a scope: it shows that systemd applied every limit.
func checkLimits() int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fcboot:", err)
		return 1
	}
	cmd := scope(fmt.Sprintf("fcboot-check-%d", os.Getpid()), self, "guard", os.DevNull)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "fcboot: the scope's limits are not in force:", err)
		return 3
	}
	return 0
}

// guard runs inside the scope: peakFile, then the command. It reads the scope's own cgroup and refuses to start the
// command unless every limit is in force there (systemd-run does not fail when one is not applied), runs the command
// (none for "check"), and writes the scope's peak memory to peakFile.
func guard(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "guard: peak file missing")
		return 2
	}
	peakFile, command := args[0], args[1:]
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		fmt.Fprintln(os.Stderr, "guard:", err)
		return 3
	}
	dir := "/sys/fs/cgroup" + strings.TrimSpace(strings.TrimPrefix(string(data), "0::"))
	for file, want := range map[string]string{"memory.max": strconv.Itoa(scopeMiB << 20), "memory.swap.max": "0",
		"pids.max": strconv.Itoa(tasks), "cpu.max": cpuMax} {
		got, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil || strings.TrimSpace(string(got)) != want {
			fmt.Fprintf(os.Stderr, "guard: %s is not %q in %s: %q %v\n", file, want, dir, strings.TrimSpace(string(got)), err)
			return 3
		}
	}
	if len(command) == 0 {
		fmt.Printf("limits in force in %s: memory %d MiB, no swap, %d tasks, one CPU\n", dir, scopeMiB, tasks)
		return 0
	}
	for resource, value := range map[int]uint64{syscall.RLIMIT_NOFILE: 2048, syscall.RLIMIT_CORE: 0} {
		if err := syscall.Setrlimit(resource, &syscall.Rlimit{Cur: value, Max: value}); err != nil {
			fmt.Fprintln(os.Stderr, "guard: resource limit:", err)
			return 3
		}
	}
	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} // the jail ends with the guard
	runErr := cmd.Run()
	if peak, err := os.ReadFile(filepath.Join(dir, "memory.peak")); err == nil {
		os.WriteFile(peakFile, peak, 0o600)
	}
	var exit *exec.ExitError
	if errors.As(runErr, &exit) {
		return exit.ExitCode()
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "guard:", runErr)
		return 1
	}
	return 0
}

type result struct {
	run          int
	ready, ended time.Duration // ready is zero when the guest never reported
	peakMiB      float64
	outcome      string
	lingering    bool    // the scope outlived its kill
	checks       []check // the jail's measures, read while the VM ran
}

func boots(n int, o options) error {
	var i ids
	if o.jail {
		var err error
		if i, err = readIDs(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(o.runs, 0o700); err != nil {
		return err
	}
	out, err := os.Create(filepath.Join(o.runs, "results.tsv"))
	if err != nil {
		return err
	}
	defer out.Close()
	fmt.Fprintln(out, "run\tready_ms\tended_ms\tpeak_mib\toutcome")
	fmt.Println("run  ready    ended    peak     outcome")
	failed := 0
	for run := 1; run <= n; run++ {
		r := boot(run, o, i, run == 1)
		fmt.Fprintf(out, "%d\t%d\t%d\t%.1f\t%s\n", r.run, r.ready.Milliseconds(), r.ended.Milliseconds(), r.peakMiB, r.outcome)
		fmt.Printf("%3d  %5d ms %5d ms %5.1f MiB %s\n", r.run, r.ready.Milliseconds(), r.ended.Milliseconds(), r.peakMiB,
			r.outcome)
		for _, c := range r.checks {
			fmt.Printf("     %-5v %-38s %s\n", c.ok, c.name, c.got)
		}
		if r.outcome != "ok" {
			failed++
		}
		if r.lingering {
			return fmt.Errorf("run %d: the scope did not end within %s of its kill; stopped the series", run, killWait)
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d boots failed", failed, n)
	}
	return nil
}

// boundedWriter keeps the first limit bytes and drops the rest, so a guest cannot fill the host's disk through the
// serial device.
type boundedWriter struct {
	file  *os.File
	limit int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if keep := min(len(p), w.limit); keep > 0 {
		if _, err := w.file.Write(p[:keep]); err != nil {
			return 0, err
		}
		w.limit -= keep
	}
	return len(p), nil
}

// boot starts one VM and waits for its guest's "ready" over vsock; with inspect it reads the jail's measures while the
// guest waits for the answer.
func boot(run int, o options, i ids, inspectJail bool) result {
	r := result{run: run}
	dir := filepath.Join(o.runs, strconv.Itoa(run))
	if o.jail {
		removeAsJailRoot(i, dir) // it may hold files of the jail's uid
	}
	os.RemoveAll(dir)
	socketDir := filepath.Join(dir, "sock") // the only directory the jailed Firecracker may write
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		r.outcome = err.Error()
		return r
	}
	listener, err := net.Listen("unix", filepath.Join(socketDir, "v.sock_52"))
	if err != nil {
		r.outcome = err.Error()
		return r
	}
	defer listener.Close()
	config := filepath.Join(dir, "vm.json")
	kernel, rootfs, uds := o.kernel, o.rootfs, filepath.Join(socketDir, "v.sock")
	if o.jail {
		kernel, rootfs, uds = "/fc/vmlinux", "/fc/rootfs.ext4", "/vm/v.sock"
	}
	if err := writeConfig(config, kernel, rootfs, uds); err != nil {
		r.outcome = err.Error()
		return r
	}
	log, err := os.Create(filepath.Join(dir, "firecracker.log"))
	if err != nil {
		r.outcome = err.Error()
		return r
	}
	defer log.Close()
	self, err := os.Executable()
	if err != nil {
		r.outcome = err.Error()
		return r
	}
	unit := fmt.Sprintf("fcboot-%d-%d", os.Getpid(), run)
	peakFile := filepath.Join(dir, "peak")
	command := []string{o.firecracker, "--no-api", "--config-file", config, "--id", unit}
	if o.jail {
		command = jailArgs(o, i, config, socketDir, unit)
	}
	cmd := scope(unit, append([]string{self, "guard", peakFile}, command...)...)
	bounded := &boundedWriter{file: log, limit: logBytes}
	cmd.Stdout, cmd.Stderr = bounded, bounded

	start := time.Now()
	if err := cmd.Start(); err != nil {
		r.outcome = err.Error()
		return r
	}
	ready := make(chan time.Duration, 1)
	checks := make(chan []check, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))
		line, _ := bufio.NewReader(io.LimitReader(conn, 64)).ReadString('\n')
		if line == "ready\n" {
			ready <- time.Since(start)
			if o.jail && inspectJail {
				checks <- inspect(o, i, unit) // the guest waits for "ok", so Firecracker is still running
			}
			conn.Write([]byte("ok\n"))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		r.outcome = "timeout; "
		if kerr := exec.Command("systemctl", "--user", "kill", "--signal=KILL", unit+".scope").Run(); kerr != nil {
			r.outcome += "kill failed: " + kerr.Error() + "; "
		}
		select {
		case err = <-done:
		case <-time.After(killWait):
			r.ended, r.lingering = time.Since(start), true
			r.outcome += "still running after the kill"
			return r
		}
	}
	r.ended = time.Since(start)
	select {
	case r.ready = <-ready:
	default:
	}
	select {
	case r.checks = <-checks:
	default:
	}
	failedChecks := 0
	for _, c := range r.checks {
		if !c.ok {
			failedChecks++
		}
	}
	if peak, err := os.ReadFile(peakFile); err == nil {
		if bytes, err := strconv.ParseFloat(strings.TrimSpace(string(peak)), 64); err == nil {
			r.peakMiB = bytes / (1 << 20)
		}
	}
	switch {
	case err != nil:
		r.outcome += "exit: " + err.Error()
	case r.ready == 0:
		r.outcome += "no ready from the guest"
	case o.jail && inspectJail && len(r.checks) == 0:
		r.outcome += "jail not checked"
	case failedChecks > 0:
		r.outcome += fmt.Sprintf("%d jail checks failed", failedChecks)
	default:
		r.outcome += "ok"
	}
	return r
}

// writeConfig writes the Firecracker configuration: no network interface, no serial console, the root image read-only
// and one vsock device. Its paths are as Firecracker sees them. The jail's uid must read it; it holds no secret.
//
// Boot arguments replace Firecracker's default command line whole, so they repeat its i8042 parameters: without them a
// kernel with the AT keyboard driver, as Firecracker's CI kernels have it, spends about half a second probing a keyboard
// that is not there.
func writeConfig(path, kernel, rootfs, uds string) error {
	config := map[string]any{
		"boot-source": map[string]any{
			"kernel_image_path": kernel,
			"boot_args":         "reboot=k panic=1 ro init=/init 8250.nr_uarts=0 i8042.noaux i8042.nomux i8042.dumbkbd quiet",
		},
		"drives": []any{map[string]any{
			"drive_id": "rootfs", "path_on_host": rootfs, "is_root_device": true, "is_read_only": true,
		}},
		"machine-config": map[string]any{"vcpu_count": 1, "mem_size_mib": guestMiB},
		"vsock":          map[string]any{"guest_cid": 3, "uds_path": uds},
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
