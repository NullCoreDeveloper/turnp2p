package turn

import (
	"context"
	"testing"
	"time"

	"turnp2p/core/p2p"
)

func TestLiveP2PDiscoveryProbe(t *testing.T) {
	vkLink := "https://vk.com/call/join/VjlpELgebDr_IGvu8b--u4Qh3eW4t3yoKUqhjEJTlRU"
	obfKey := "1fe6696c763a333fa5394c5778231dd1b08d3ac7e254d3ad4b156f9162216563"

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	t.Logf("[Diag] Fetching VK credentials...")
	creds, err := FetchVKTurnCredentials(ctx, vkLink)
	if err != nil {
		t.Fatalf("Failed to get credentials: %v", err)
	}
	t.Logf("[Diag] TURN Credentials: %+v", creds)

	t.Logf("[Diag] Allocating bonded connection (5 streams, rtpopus3)...")
	conn, err := AllocateMultiStreamClient(ctx, creds, obfKey, 5)
	if err != nil {
		t.Fatalf("Failed to allocate multi-stream: %v", err)
	}
	defer conn.Close()

	node := p2p.NewMeshNode("DiagBot", "diagbot.vkturn", "")
	peersFound := make(chan p2p.Peer, 10)

	node.SetPeerCallback(func(peers []p2p.Peer) {
		for _, p := range peers {
			t.Logf("[Diag EVENT] Discovered active peer: Name=%s, Domain=%s, IP=%s, Ports=%v, Ping=%dms",
				p.Name, p.Domain, p.VirtualIP, p.SharedPorts, p.Ping)
			peersFound <- p
		}
	})

	if err := node.Start(context.Background(), conn); err != nil {
		t.Fatalf("Failed to start mesh node: %v", err)
	}
	defer node.Stop()

	t.Logf("[Diag] Node started. Local relay: %s. Listening for active peers for 10 seconds...", conn.LocalAddr())

	select {
	case p := <-peersFound:
		t.Logf("[Diag SUCCESS] Peer detected! %s (%s, %s)", p.Name, p.Domain, p.VirtualIP)
	case <-time.After(10 * time.Second):
		t.Logf("[Diag INFO] 10s listen period elapsed. Active peers count: %d", len(node.GetPeers()))
	}
}
