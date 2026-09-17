//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	cIFF_TUN   = 0x0001
	cIFF_NO_PI = 0x1000
)

type ifreq struct {
	Name  [16]byte
	Flags uint16
	_pad  [22]byte
}

type linuxDevice struct {
	file *os.File
	name string
	ip   string
}

// OpenDevice creates and configures a Linux TUN interface (e.g. turnp2p0) with assigned virtual IP.
func OpenDevice(name string, virtualIP string) (Device, error) {
	if name == "" {
		name = "turnp2p0"
	}

	if err := configureInterface(name, virtualIP); err != nil {
		return nil, err
	}

	return tryOpenTun(name, virtualIP)
}

func configureInterface(name string, virtualIP string) error {
	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = "root"
	}

	script := fmt.Sprintf(`ip tuntap add dev %[1]s mode tun user %[2]s 2>/dev/null || true
ip addr flush dev %[1]s 2>/dev/null || true
ip addr add %[3]s/16 dev %[1]s
ip link set dev %[1]s mtu 1280 up
ip route replace 10.42.0.0/16 dev %[1]s 2>/dev/null || true`, name, currentUser, virtualIP)

	if os.Geteuid() == 0 {
		return exec.Command("sh", "-c", script).Run()
	}

	// Try without pkexec first (in case user has capabilities or sudo rules)
	if err := exec.Command("sh", "-c", script).Run(); err == nil {
		return nil
	}

	// Elevate via pkexec
	cmd := exec.Command("pkexec", "sh", "-c", script)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure TUN interface %s via pkexec: %w", name, err)
	}
	return nil
}

func tryOpenTun(name string, virtualIP string) (Device, error) {
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var req ifreq
	req.Flags = cIFF_TUN | cIFF_NO_PI
	copy(req.Name[:], []byte(name))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("ioctl TUNSETIFF on %s failed: %w", name, errno)
	}

	actualName := string(req.Name[:])
	if idx := stringsIndexNull(actualName); idx != -1 {
		actualName = actualName[:idx]
	}

	f := os.NewFile(uintptr(fd), "/dev/net/tun")

	return &linuxDevice{
		file: f,
		name: actualName,
		ip:   virtualIP,
	}, nil
}

func (d *linuxDevice) Read(p []byte) (n int, err error) {
	return d.file.Read(p)
}

func (d *linuxDevice) Write(p []byte) (n int, err error) {
	return d.file.Write(p)
}

func (d *linuxDevice) Close() error {
	var closeErr error
	if d.file != nil {
		closeErr = d.file.Close()
	}
	_ = exec.Command("ip", "link", "delete", "dev", d.name).Run()
	_ = exec.Command("ip", "tuntap", "del", "dev", d.name, "mode", "tun").Run()
	return closeErr
}

func (d *linuxDevice) Name() string { return d.name }
func (d *linuxDevice) IP() string   { return d.ip }

func stringsIndexNull(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 {
			return i
		}
	}
	return -1
}
