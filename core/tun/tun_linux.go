//go:build linux

package tun

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
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

// EnsureCapabilities checks if the current binary has CAP_NET_ADMIN.
// If not, it requests elevation once via pkexec to setcap cap_net_admin,cap_net_raw+eip on itself.
func EnsureCapabilities() error {
	if os.Geteuid() == 0 {
		return nil
	}

	// 1. Check if we can already open /dev/net/tun directly
	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0)
	if err == nil {
		var req ifreq
		req.Flags = cIFF_TUN | cIFF_NO_PI
		copy(req.Name[:], []byte("turnp2ptest%d"))
		_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req)))
		_ = syscall.Close(fd)
		if errno == 0 {
			// Already has capabilities, raise ambient capability so child tools (ip) inherit it
			_ = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(unix.CAP_NET_ADMIN), 0, 0)
			return nil
		}
	}

	// 2. We lack capabilities, find path to self
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return fmt.Errorf("cannot resolve executable path: %w", err)
	}

	log.Printf("[TUN] Requesting cap_net_admin,cap_net_raw for %s via pkexec...", exe)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pkexec", "setcap", "cap_net_admin,cap_net_raw+eip", exe)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to grant capabilities via pkexec: %w", err)
	}

	log.Printf("[TUN] Successfully granted network capabilities to %s!", exe)
	_ = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(unix.CAP_NET_ADMIN), 0, 0)
	return nil
}

// OpenDevice creates and configures a Linux TUN interface (e.g. turnp2p0) with assigned virtual IP.
func OpenDevice(name string, virtualIP string) (Device, error) {
	if name == "" {
		name = "turnp2p0"
	}

	// Try to ensure capabilities first
	if capErr := EnsureCapabilities(); capErr != nil {
		log.Printf("[TUN] EnsureCapabilities warning: %v", capErr)
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

	script := fmt.Sprintf(`set -e
ip tuntap add dev %[1]s mode tun user %[2]s 2>/dev/null || true
ip addr flush dev %[1]s 2>/dev/null || true
ip addr add %[3]s/16 dev %[1]s
ip link set dev %[1]s mtu 1280 up
ip route replace 10.42.0.0/16 dev %[1]s 2>/dev/null || true
iptables -I INPUT -i %[1]s -j ACCEPT 2>/dev/null || true
iptables -I FORWARD -i %[1]s -j ACCEPT 2>/dev/null || true
firewall-cmd --zone=trusted --add-interface=%[1]s 2>/dev/null || true
ufw allow in on %[1]s 2>/dev/null || true
sysctl -w net.ipv4.conf.%[1]s.rp_filter=0 2>/dev/null || true`, name, currentUser, virtualIP)

	if os.Geteuid() == 0 {
		return exec.Command("sh", "-c", script).Run()
	}

	// Raise ambient capability so child processes (ip) inherit CAP_NET_ADMIN
	_ = unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(unix.CAP_NET_ADMIN), 0, 0)

	// Try without pkexec first
	ctxDirect, cancelDirect := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelDirect()
	if err := exec.CommandContext(ctxDirect, "sh", "-c", script).Run(); err == nil {
		return nil
	}

	// Elevate via pkexec with strict timeout to prevent hangs
	ctxPk, cancelPk := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelPk()

	cmd := exec.CommandContext(ctxPk, "pkexec", "sh", "-c", script)
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
	_ = exec.Command("sh", "-c", fmt.Sprintf(`
iptables -D INPUT -i %[1]s -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i %[1]s -j ACCEPT 2>/dev/null || true
firewall-cmd --zone=trusted --remove-interface=%[1]s 2>/dev/null || true
ufw delete allow in on %[1]s 2>/dev/null || true
ip link delete dev %[1]s 2>/dev/null || true
ip tuntap del dev %[1]s mode tun 2>/dev/null || true
`, d.name)).Run()
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
