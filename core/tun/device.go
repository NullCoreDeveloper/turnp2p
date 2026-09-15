package tun

import (
	"io"
)

// Device represents a network TUN interface.
type Device interface {
	io.ReadWriteCloser
	Name() string
	IP() string
}
