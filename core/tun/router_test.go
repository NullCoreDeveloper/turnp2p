package tun

import (
	"context"
	"net"
	"testing"
	"time"

	"turnp2p/core/p2p"
)

type mockTunDevice struct {
	name      string
	ip        string
	readChan  chan []byte
	writeChan chan []byte
	closed    bool
}

func newMockTunDevice(name string, ip string) *mockTunDevice {
	return &mockTunDevice{
		name:      name,
		ip:        ip,
		readChan:  make(chan []byte, 32),
		writeChan: make(chan []byte, 32),
	}
}

func (m *mockTunDevice) Read(p []byte) (n int, err error) {
	pkt, ok := <-m.readChan
	if !ok {
		return 0, net.ErrClosed
	}
	n = copy(p, pkt)
	return n, nil
}

func (m *mockTunDevice) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, net.ErrClosed
	}
	b := make([]byte, len(p))
	copy(b, p)
	m.writeChan <- b
	return len(p), nil
}

func (m *mockTunDevice) Close() error {
	m.closed = true
	close(m.readChan)
	return nil
}

func (m *mockTunDevice) Name() string { return m.name }
func (m *mockTunDevice) IP() string   { return m.ip }

type pipePacketConn struct {
	localAddr net.Addr
	readChan  chan []byte
	peerConn  *pipePacketConn
	closed    bool
}

func newPipePacketConnPair() (*pipePacketConn, *pipePacketConn) {
	p1 := &pipePacketConn{
		localAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 19302},
		readChan:  make(chan []byte, 64),
	}
	p2 := &pipePacketConn{
		localAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 19302},
		readChan:  make(chan []byte, 64),
	}
	p1.peerConn = p2
	p2.peerConn = p1
	return p1, p2
}

func (p *pipePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	data, ok := <-p.readChan
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(b, data)
	return n, p.peerConn.localAddr, nil
}

func (p *pipePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.closed {
		return 0, net.ErrClosed
	}
	data := make([]byte, len(b))
	copy(data, b)
	p.peerConn.readChan <- data
	return len(b), nil
}

func (p *pipePacketConn) Close() error                       { p.closed = true; return nil }
func (p *pipePacketConn) LocalAddr() net.Addr                { return p.localAddr }
func (p *pipePacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipePacketConn) SetWriteDeadline(t time.Time) error { return nil }

func buildMockIPv4Packet(srcIP, dstIP net.IP, payload []byte) []byte {
	// 20-byte standard IPv4 header
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	pkt[1] = 0x00
	totalLen := 20 + len(payload)
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP protocol
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())
	copy(pkt[20:], payload)
	return pkt
}

func TestTUNRouterBidirectionalFlow(t *testing.T) {
	connA, connB := newPipePacketConnPair()

	nodeA := p2p.NewMeshNode("NodeA", "nodea.vkturn", "10.42.0.1")
	nodeB := p2p.NewMeshNode("NodeB", "nodeb.vkturn", "10.42.0.2")
	nodeA.SetFirewallMode(p2p.FirewallModeAllowAll)
	nodeB.SetFirewallMode(p2p.FirewallModeAllowAll)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = nodeA.Start(ctx, connA)
	defer nodeA.Stop()
	_ = nodeB.Start(ctx, connB)
	defer nodeB.Stop()

	// Discovery
	_ = nodeA.PingAddress(connB.LocalAddr())
	time.Sleep(100 * time.Millisecond)

	devA := newMockTunDevice("turnp2p0", "10.42.0.1")
	devB := newMockTunDevice("turnp2p1", "10.42.0.2")

	routerA := NewRouter(devA, nodeA)
	routerB := NewRouter(devB, nodeB)

	if err := routerA.Start(ctx); err != nil {
		t.Fatalf("start routerA: %v", err)
	}
	defer routerA.Stop()

	if err := routerB.Start(ctx); err != nil {
		t.Fatalf("start routerB: %v", err)
	}
	defer routerB.Stop()

	// 1. Inject IPv4 packet into devA with Destination 10.42.0.2
	testPayload := []byte("PING_FROM_TUN_A")
	ipPkt := buildMockIPv4Packet(net.ParseIP("10.42.0.1"), net.ParseIP("10.42.0.2"), testPayload)

	devA.readChan <- ipPkt

	// 2. Expect packet to arrive on devB.writeChan via P2P mesh
	select {
	case receivedPkt := <-devB.writeChan:
		if len(receivedPkt) != len(ipPkt) {
			t.Fatalf("received packet len mismatch: got %d, want %d", len(receivedPkt), len(ipPkt))
		}
		extractedPayload := string(receivedPkt[20:])
		if extractedPayload != string(testPayload) {
			t.Fatalf("payload mismatch: got %q, want %q", extractedPayload, string(testPayload))
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for IP packet on devB")
	}
}
