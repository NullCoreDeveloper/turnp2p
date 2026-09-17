package tun

import (
	"context"
	"encoding/binary"
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

		// Extract IPs from IPv4 header
		srcIP := net.IPv4(buf[12], buf[13], buf[14], buf[15])
		dstIPStr := net.IPv4(buf[16], buf[17], buf[18], buf[19]).String()

		class := p2p.ClassifyIP(dstIPStr)
		if class == p2p.IPClassLocal || class == p2p.IPClassUnknown {
			continue // Do not forward local or invalid packets to the mesh
		}

		// Forward IPv4 packet into P2P mesh, fragmenting if necessary (Safe MTU for TURN is ~1200)
		packetData := make([]byte, n)
		copy(packetData, buf[:n])

		// Perform SNAT for broadcast/multicast discovery packets originating from 0.0.0.0
		if class == p2p.IPClassBroadcast || class == p2p.IPClassMulticast {
			if srcIP.Equal(net.IPv4zero) {
				_, _, myIP, _ := r.node.GetInfo()
				parsedMyIP := net.ParseIP(myIP).To4()
				if parsedMyIP != nil {
					copy(packetData[12:16], parsedMyIP)
					p2p.RecalculateIPv4Checksum(packetData)
				}
			}
		}

		fragments := fragmentIPv4(packetData, 1200)
		for _, frag := range fragments {
			if err := r.node.SendRawIP(dstIPStr, frag); err != nil {
				r.logSendError(dstIPStr, err)
			}
		}
	}
}

// fragmentIPv4 splits a large IPv4 packet into standard fragments if it exceeds the MTU.
func fragmentIPv4(packet []byte, mtu int) [][]byte {
	if len(packet) <= mtu {
		return [][]byte{packet}
	}

	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl {
		return nil
	}

	maxPayload := ((mtu - ihl) / 8) * 8
	if maxPayload <= 0 {
		return nil // MTU too small
	}

	origPayload := packet[ihl:]
	origFlags := binary.BigEndian.Uint16(packet[6:8])
	origOffset := (origFlags & 0x1FFF) * 8

	var fragments [][]byte

	for offset := 0; offset < len(origPayload); offset += maxPayload {
		chunkLen := maxPayload
		if offset+chunkLen > len(origPayload) {
			chunkLen = len(origPayload) - offset
		}

		frag := make([]byte, ihl+chunkLen)
		copy(frag[:ihl], packet[:ihl])
		copy(frag[ihl:], origPayload[offset:offset+chunkLen])

		// Update Total Length
		binary.BigEndian.PutUint16(frag[2:4], uint16(len(frag)))

		// Update Flags and Fragment Offset
		fragOffset := (int(origOffset) + offset) / 8
		flags := origFlags & 0x8000 // preserve reserved bit
		if offset+chunkLen < len(origPayload) || (origFlags&0x2000) != 0 {
			flags |= 0x2000 // Set More Fragments (MF) flag
		}
		flags |= uint16(fragOffset & 0x1FFF)
		binary.BigEndian.PutUint16(frag[6:8], flags)

		// Recompute IP Checksum
		frag[10] = 0
		frag[11] = 0
		var csum uint32
		for i := 0; i < ihl; i += 2 {
			csum += uint32(frag[i])<<8 | uint32(frag[i+1])
		}
		for csum > 0xffff {
			csum = (csum >> 16) + (csum & 0xffff)
		}
		csum = ^csum
		binary.BigEndian.PutUint16(frag[10:12], uint16(csum))

		fragments = append(fragments, frag)
	}

	return fragments
}

func (r *Router) logSendError(dstIP string, err error) {
	now := time.Now()
	if now.Sub(r.lastErrLog) > 3*time.Second || r.lastErrDst != dstIP {
		r.lastErrLog = now
		r.lastErrDst = dstIP
		log.Printf("[TUN Router] Cannot forward L3 packet to %s: %v", dstIP, err)
	}
}
