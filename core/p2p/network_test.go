package p2p

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"turnp2p/core/obf"
)

type pipePacketConn struct {
	localAddr net.Addr
	readChan  chan packet
	peerConn  *pipePacketConn
	closed    bool
}

type packet struct {
	data []byte
	addr net.Addr
}

func newPipePacketConnPair() (*pipePacketConn, *pipePacketConn) {
	addrA := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 19302}
	addrB := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 19302}

	connA := &pipePacketConn{
		localAddr: addrA,
		readChan:  make(chan packet, 128),
	}
	connB := &pipePacketConn{
		localAddr: addrB,
		readChan:  make(chan packet, 128),
	}

	connA.peerConn = connB
	connB.peerConn = connA

	return connA, connB
}

func (p *pipePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pkt, ok := <-p.readChan
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(b, pkt.data)
	return n, pkt.addr, nil
}

func (p *pipePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.closed {
		return 0, net.ErrClosed
	}
	data := make([]byte, len(b))
	copy(data, b)
	p.peerConn.readChan <- packet{data: data, addr: p.localAddr}
	return len(b), nil
}

func (p *pipePacketConn) Close() error {
	p.closed = true
	return nil
}

func (p *pipePacketConn) LocalAddr() net.Addr                { return p.localAddr }
func (p *pipePacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipePacketConn) SetWriteDeadline(t time.Time) error { return nil }

// Test 1: Basic discovery, mutual handshake, whitelist firewall, and bidirectional data exchange
func TestP2PDiscoveryAndDataFlow(t *testing.T) {
	connA, connB := newPipePacketConnPair()

	nodeA := NewMeshNode("Alice", "alice.vkturn", "10.42.0.1")
	nodeB := NewMeshNode("Bob", "bob.vkturn", "10.42.0.2")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := nodeA.Start(ctx, connA); err != nil {
		t.Fatalf("start nodeA: %v", err)
	}
	defer nodeA.Stop()

	if err := nodeB.Start(ctx, connB); err != nil {
		t.Fatalf("start nodeB: %v", err)
	}
	defer nodeB.Stop()

	nodeA.PingAddress(connB.LocalAddr())
	time.Sleep(100 * time.Millisecond)

	peersA := nodeA.GetPeers()
	if len(peersA) == 0 {
		t.Fatalf("Node A did not discover Node B")
	}

	if peersA[0].Name != "Bob" || peersA[0].VirtualIP != "10.42.0.2" || peersA[0].Domain != "bob.vkturn" {
		t.Fatalf("unexpected peer details for Bob: %+v", peersA[0])
	}

	// Verify Firewall: Port 8080 should be blocked by default (whitelist mode)
	dialCtx, dialCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer dialCancel()
	_, err := nodeA.Dial(dialCtx, "bob.vkturn", 8080)
	if err == nil {
		t.Fatalf("expected dial to blocked port 8080 to fail")
	}

	// Allow port 8080 on Node B
	nodeB.AllowPort(8080)

	// Start local server on Node B at 127.0.0.1:8080
	localSrv, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("local listen: %v", err)
	}
	defer localSrv.Close()

	go func() {
		conn, err := localSrv.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 12)
		io.ReadFull(conn, buf)
		conn.Write([]byte("HELLO_FROM_B"))
	}()

	// Dial bob.vkturn:8080 from Node A
	stream, err := nodeA.Dial(ctx, "bob.vkturn", 8080)
	if err != nil {
		t.Fatalf("dial bob.vkturn:8080: %v", err)
	}
	defer stream.Close()

	stream.Write([]byte("PING_FROM_A_"))
	resp := make([]byte, 12)
	_, err = io.ReadFull(stream, resp)
	if err != nil {
		t.Fatalf("read stream: %v", err)
	}

	if string(resp) != "HELLO_FROM_B" {
		t.Fatalf("unexpected response: %q", string(resp))
	}
}

// Test 2: Custom domain announcement, live domain change on the fly, and communication via new domain
func TestP2PDomainAnnouncementAndDynamicUpdate(t *testing.T) {
	connA, connB := newPipePacketConnPair()

	nodeA := NewMeshNode("ServerHost", "initial.vkturn", "10.42.1.10")
	nodeB := NewMeshNode("ClientGuest", "guest.vkturn", "10.42.1.20")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = nodeA.Start(ctx, connA)
	defer nodeA.Stop()
	_ = nodeB.Start(ctx, connB)
	defer nodeB.Stop()

	// Initial discovery
	_ = nodeB.PingAddress(connA.LocalAddr())
	time.Sleep(100 * time.Millisecond)

	peersB := nodeB.GetPeers()
	if len(peersB) == 0 || peersB[0].Domain != "initial.vkturn" {
		t.Fatalf("expected peer domain initial.vkturn, got %+v", peersB)
	}

	// Change domain dynamically on Node A to "craft-server.vkturn"
	nodeA.SetCustomDomain("craft-server.vkturn")
	nodeA.AllowPort(25565)

	// Trigger heartbeat announcement with new domain
	_ = nodeA.PingAddress(connB.LocalAddr())
	time.Sleep(100 * time.Millisecond)

	peersB = nodeB.GetPeers()
	if peersB[0].Domain != "craft-server.vkturn" {
		t.Fatalf("expected updated domain craft-server.vkturn, got %s", peersB[0].Domain)
	}

	// Start Minecraft dummy service on Node A
	localMC, err := net.Listen("tcp", "127.0.0.1:25565")
	if err != nil {
		t.Fatalf("listen 25565: %v", err)
	}
	defer localMC.Close()

	go func() {
		conn, err := localMC.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 10)
		io.ReadFull(conn, buf)
		conn.Write([]byte("PONG_MC_OK"))
	}()

	// Connect using the newly updated domain name "craft-server.vkturn"
	stream, err := nodeB.Dial(ctx, "craft-server.vkturn", 25565)
	if err != nil {
		t.Fatalf("failed to dial craft-server.vkturn: %v", err)
	}
	defer stream.Close()

	stream.Write([]byte("PING_MC_01"))
	resp := make([]byte, 10)
	io.ReadFull(stream, resp)
	if string(resp) != "PONG_MC_OK" {
		t.Fatalf("unexpected MC response: %q", string(resp))
	}
}

// Test 3: End-to-end communication through rtpopus3 encrypted & obfuscated tunnel
func TestP2PObfuscatedTunnelRTPOpus3(t *testing.T) {
	rawA, rawB := newPipePacketConnPair()

	// 64-character hex key (32 bytes)
	keyBytes := make([]byte, 32)
	rand.Read(keyBytes)
	keyHex := hex.EncodeToString(keyBytes)

	obfA, err := obf.NewRTPOpus3(keyHex)
	if err != nil {
		t.Fatalf("create obfA: %v", err)
	}
	obfB, err := obf.NewRTPOpus3(keyHex)
	if err != nil {
		t.Fatalf("create obfB: %v", err)
	}

	tunA := obf.NewObfuscatedPacketConn(rawA, obfA)
	tunB := obf.NewObfuscatedPacketConn(rawB, obfB)

	nodeA := NewMeshNode("SecureAlice", "secure-alice.vkturn", "10.42.3.1")
	nodeB := NewMeshNode("SecureBob", "secure-bob.vkturn", "10.42.3.2")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = nodeA.Start(ctx, tunA)
	defer nodeA.Stop()
	_ = nodeB.Start(ctx, tunB)
	defer nodeB.Stop()

	nodeA.AllowPort(9000)

	// Discover
	_ = nodeB.PingAddress(tunA.LocalAddr())
	time.Sleep(100 * time.Millisecond)

	// Start local service
	srv, err := net.Listen("tcp", "127.0.0.1:9000")
	if err != nil {
		t.Fatalf("listen 9000: %v", err)
	}
	defer srv.Close()

	go func() {
		conn, err := srv.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		io.ReadFull(conn, buf)
		conn.Write([]byte("SECURE_OPUS_ACK!"))
	}()

	stream, err := nodeB.Dial(ctx, "secure-alice.vkturn", 9000)
	if err != nil {
		t.Fatalf("dial secure-alice.vkturn: %v", err)
	}
	defer stream.Close()

	stream.Write([]byte("HELLO_ENCRYPTED!"))
	resp := make([]byte, 16)
	io.ReadFull(stream, resp)

	if string(resp) != "SECURE_OPUS_ACK!" {
		t.Fatalf("unexpected secure response: %q", string(resp))
	}
}

// Test 4: Firewall modes (allow_all, block_all, whitelist)
func TestP2PFirewallModes(t *testing.T) {
	connA, connB := newPipePacketConnPair()

	nodeA := NewMeshNode("FirewallTester", "target.vkturn", "10.42.9.1")
	nodeB := NewMeshNode("Scanner", "scanner.vkturn", "10.42.9.2")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = nodeA.Start(ctx, connA)
	defer nodeA.Stop()
	_ = nodeB.Start(ctx, connB)
	defer nodeB.Stop()

	_ = nodeB.PingAddress(connA.LocalAddr())
	time.Sleep(100 * time.Millisecond)

	// 1. Block All
	nodeA.SetFirewallMode(FirewallModeBlockAll)
	dialCtx1, cancel1 := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel1()
	_, err := nodeB.Dial(dialCtx1, "target.vkturn", 5000)
	if err == nil {
		t.Fatalf("expected dial to fail under block_all")
	}

	// 2. Allow All
	nodeA.SetFirewallMode(FirewallModeAllowAll)
	srv, _ := net.Listen("tcp", "127.0.0.1:5000")
	defer srv.Close()

	go func() {
		c, err := srv.Accept()
		if err == nil {
			c.Close()
		}
	}()

	stream, err := nodeB.Dial(ctx, "target.vkturn", 5000)
	if err != nil {
		t.Fatalf("expected dial to succeed under allow_all: %v", err)
	}
	stream.Close()
}

func TestP2PRawIPFirewall(t *testing.T) {
	node := NewMeshNode("Tester", "tester.vkturn", "10.42.0.1")

	// Build a mock IPv4 UDP packet targeting port 8080
	// 20 bytes IPv4 header + 8 bytes UDP header
	pkt := make([]byte, 28)
	pkt[0] = 0x45
	pkt[9] = 17 // UDP
	// Dest port 8080 (0x1F90)
	pkt[22] = 0x1F
	pkt[23] = 0x90

	// 1. Default whitelist: port 8080 not allowed
	node.SetFirewallMode(FirewallModeWhitelist)
	if node.isRawIPAllowed(pkt) {
		t.Errorf("expected port 8080 to be blocked under whitelist")
	}

	// 2. Allow port 8080
	node.AllowPort(8080)
	if !node.isRawIPAllowed(pkt) {
		t.Errorf("expected port 8080 to be allowed after AllowPort")
	}

	// 3. Block all
	node.SetFirewallMode(FirewallModeBlockAll)
	if node.isRawIPAllowed(pkt) {
		t.Errorf("expected port 8080 to be blocked under block_all")
	}

	// 4. Allow all
	node.SetFirewallMode(FirewallModeAllowAll)
	if !node.isRawIPAllowed(pkt) {
		t.Errorf("expected port 8080 to be allowed under allow_all")
	}
}

