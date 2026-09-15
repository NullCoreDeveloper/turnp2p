package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"turnp2p/core/p2p"
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

func TestProxyManagerLifecycle(t *testing.T) {
	mgr := NewManager(nil)
	if mgr == nil {
		t.Fatal("failed to create manager")
	}

	rule := ForwardingRule{
		ID:         "rule-1",
		Name:       "Test HTTP",
		Protocol:   "TCP",
		LocalPort:  18080,
		RemoteIP:   "10.42.0.2",
		RemotePort: 80,
	}

	err := mgr.AddRule(rule)
	if err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	rules := mgr.ListRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	// Adding duplicate port should fail
	err = mgr.AddRule(rule)
	if err == nil {
		t.Fatal("expected error when adding rule with duplicate local port")
	}

	// Remove rule
	err = mgr.RemoveRule("rule-1")
	if err != nil {
		t.Fatalf("failed to remove rule: %v", err)
	}

	if len(mgr.ListRules()) != 0 {
		t.Fatalf("expected 0 rules after removal")
	}

	_ = mgr.Stop()
}

func TestP2PPortForwardingOverDomain(t *testing.T) {
	connA, connB := newPipePacketConnPair()

	nodeServer := p2p.NewMeshNode("WebServer", "web.vkturn", "10.42.5.1")
	nodeClient := p2p.NewMeshNode("WebClient", "client.vkturn", "10.42.5.2")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_ = nodeServer.Start(ctx, connA)
	defer nodeServer.Stop()
	_ = nodeClient.Start(ctx, connB)
	defer nodeClient.Stop()

	// 1. Start HTTP test server on WebServer host (127.0.0.1:8899)
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "VK_TURN_P2P_HTTP_RESPONSE_OK")
	}))
	defer httpServer.Close()

	httpPort := httpServer.Listener.Addr().(*net.TCPAddr).Port
	nodeServer.AllowPort(httpPort)

	// Discover
	_ = nodeClient.PingAddress(connA.LocalAddr())
	time.Sleep(100 * time.Millisecond)

	// 2. Set up Port Forwarding rule on WebClient: 127.0.0.1:19999 -> web.vkturn:<httpPort>
	mgr := NewManager(nodeClient)
	defer mgr.Stop()

	rule := ForwardingRule{
		ID:         "test-http-fwd",
		Name:       "Web Tunnel",
		LocalPort:  19999,
		RemoteIP:   "web.vkturn",
		RemotePort: httpPort,
		Protocol:   "tcp",
		Enabled:    true,
	}

	if err := mgr.AddRule(rule); err != nil {
		t.Fatalf("add forward rule: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// 3. Make HTTP request to local forward port 127.0.0.1:19999
	resp, err := http.Get("http://127.0.0.1:19999/")
	if err != nil {
		t.Fatalf("http GET to forwarded port failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if string(body) != "VK_TURN_P2P_HTTP_RESPONSE_OK" {
		t.Fatalf("unexpected HTTP body: %q", string(body))
	}
}
