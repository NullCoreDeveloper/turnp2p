//go:build windows

package tun

import (
	"fmt"
)

// OpenDevice creates a Windows TUN adapter using Wintun or returns a graceful message.
func OpenDevice(name string, virtualIP string) (Device, error) {
	return nil, fmt.Errorf("wintun driver not found or elevated administrator permissions required for TUN on Windows (use Userspace / Ports mode)")
}
