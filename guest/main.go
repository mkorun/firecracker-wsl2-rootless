// Command guest is PID 1 of the test VM. It tells the host over vsock that it runs, waits for the host's answer, then
// restarts the VM, which ends Firecracker (boot argument reboot=k).
//
// The wait matters: a guest that restarts right after its write can lose the line before Firecracker passes it on.
package main

import "golang.org/x/sys/unix"

// port is the vsock port the host listens on, as <uds_path>_52.
const port = 52

func main() {
	send("ready")
	unix.Sync()
	unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
}

// send sends one line to the host and waits up to two seconds for its answer.
func send(line string) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port}); err != nil {
		return
	}
	if _, err := unix.Write(fd, []byte(line+"\n")); err != nil {
		return
	}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})
	answer := make([]byte, 3)
	unix.Read(fd, answer)
}
