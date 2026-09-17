package tun

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"turnp2p/core/p2p"
)

// Router bridges raw L3 IP packets between the OS TUN device and the P2P MeshNode.
type Router struct {
	dev         Device
	node        *p2p.MeshNode
	ctx         context.Context
	cancel      context.CancelFunc
	closed      atomic.Bool
	lastErrLog  time.Time
	lastErrDst  string
}

// NewRouter creates an L3 IP packet router.
func NewRouter(dev Device, node *p2p.MeshNode) *Router {
	return &Router{
		dev:  dev,
		node: node,
	}
}

// Start initiates bidirectional L3 packet forwarding.
func (r *Router) Start(ctx context.Context) error {
	if r.dev == nil {
		return fmt.Errorf("tun device is nil")
	}
	if r.node == nil {
		return fmt.Errorf("mesh node is nil")
	}

	r.ctx, r.cancel = context.WithCancel(ctx)
	r.closed.Store(false)

	// Register incoming P2P mesh raw IP callback -> write to OS TUN
	r.node.SetRawIPHandler(func(ipPacket []byte) {
		if r.closed.Load() {
			return
		}
		if _, err := r.dev.Write(ipPacket); err != nil {
			log.Printf("[TUN Router] Error writing incoming L3 packet to %s: %v", r.dev.Name(), err)
		}
	})

	go r.tunReadLoop()
	log.Printf("[TUN Router] Started L3 router on %s (IP: %s)", r.dev.Name(), r.dev.IP())
	return nil
}

// Stop terminates the router and closes the TUN device.
func (r *Router) Stop() error {
	if r.closed.Swap(true) {
		return nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	if r.dev != nil {
		return r.dev.Close()
	}
	return nil
}

func (r *Router) tunReadLoop() {
	buf := make([]byte, 2048)
	for !r.closed.Load() {
		n, err := r.dev.Read(buf)
		if err != nil {
			if r.closed.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if n < 20 {
			continue // Minimum IPv4 header size
		}

		// Verify IPv4
		version := buf[0] >> 4
		if version != 4 {
			continue
		}

		// Destination IP: bytes 16..19 in IPv4 header
		dstIP := net.IPv4(buf[16], buf[17], buf[18], buf[19]).String()

		// Forward IPv4 packet into P2P mesh
		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		if err := r.node.SendRawIP(dstIP, packetData); err != nil {
			r.logSendError(dstIP, err)
			continue
		}
	}
}

func (r *Router) logSendError(dstIP string, err error) {
	now := time.Now()
	if now.Sub(r.lastErrLog) > 3*time.Second || r.lastErrDst != dstIP {
		r.lastErrLog = now
		r.lastErrDst = dstIP
		log.Printf("[TUN Router] Cannot forward L3 packet to %s: %v", dstIP, err)
	}
}
