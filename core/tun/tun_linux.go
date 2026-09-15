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

	fd, err := syscall.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w (root/CAP_NET_ADMIN required for TUN mode)", err)
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

	// Configure IP and bring interface up
	if virtualIP != "" {
		_ = exec.Command("ip", "addr", "add", virtualIP+"/16", "dev", actualName).Run()
		_ = exec.Command("ip", "link", "set", "dev", actualName, "up").Run()
		_ = exec.Command("ip", "route", "add", "10.42.0.0/16", "dev", actualName).Run()
	}

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
	_ = exec.Command("ip", "link", "set", "dev", d.name, "down").Run()
	return d.file.Close()
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
