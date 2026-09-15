package turn

import (
	"context"
	"testing"
	"time"

	"turnp2p/core/p2p"
)

func TestLiveJoinAndDiscoverUser(t *testing.T) {
	vkLink := "https://vk.com/call/join/VjlpELgebDr_IGvu8b--u4Qh3eW4t3yoKUqhjEJTlRU"
	obfKey := "1fe6696c763a333fa5394c5778231dd1b08d3ac7e254d3ad4b156f9162216563"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Logf("[Live Bot] Fetching credentials for VK call: %s...", vkLink)
	creds, err := FetchVKTurnCredentials(ctx, vkLink)
	if err != nil {
		t.Fatalf("Failed to get credentials: %v", err)
	}

	t.Logf("[Live Bot] TURN Server: %s, Username: %s", creds.ServerAddr, creds.Username)
	t.Logf("[Live Bot] WsEndpoint: %s", creds.WsEndpoint)

	t.Logf("[Live Bot] Connecting 3 streams to TURN (rtpopus3)...")
	bondedConn, err := AllocateMultiStreamClient(ctx, creds, obfKey, 3)
	if err != nil {
		t.Fatalf("Failed multi-stream: %v", err)
	}
	defer bondedConn.Close()

	relayAddrStr := bondedConn.LocalAddr().String()
	t.Logf("[Live Bot] Bot Relay Address: %s", relayAddrStr)

	node := p2p.NewMeshNode("AntigravityBot", "bot.vkturn", "")
	peersDiscovered := make(chan p2p.Peer, 10)

	node.SetPeerCallback(func(peers []p2p.Peer) {
		for _, p := range peers {
			t.Logf("[PEER DETECTED!] Name=%s, Domain=%s, VirtualIP=%s, Relay=%s, Ping=%dms, SharedPorts=%v",
				p.Name, p.Domain, p.VirtualIP, p.RelayAddr, p.Ping, p.SharedPorts)
			peersDiscovered <- p
		}
	})

	if err := node.Start(context.Background(), bondedConn); err != nil {
		t.Fatalf("Failed node start: %v", err)
	}
	defer node.Stop()

	// Start Signaling client if wsEndpoint present
	if creds.WsEndpoint != "" {
		sig := NewSignalingClient(creds.WsEndpoint, vkLink, obfKey)
		id, name, vIP, domain := node.GetInfo()
		localInfo := SignalingPeerInfo{
			ID:        id,
			Name:      name,
			RelayAddr: relayAddrStr,
			VirtualIP: vIP,
			Domain:    domain,
		}
		sig.Start(context.Background(), localInfo, func(peerRelayAddr string) {
			t.Logf("[Live Bot Signaling] Received peer relay from WebSocket: %s, connecting...", peerRelayAddr)
			_ = node.ConnectPeer(peerRelayAddr)
		})
		defer sig.Stop()
	}

	t.Logf("[Live Bot] Listening in the room for 15 seconds...")
	select {
	case p := <-peersDiscovered:
		t.Logf("[SUCCESS!] Successfully discovered user client in room: %s (%s, %s, ping=%dms)",
			p.Name, p.Domain, p.VirtualIP, p.Ping)
	case <-time.After(15 * time.Second):
		t.Logf("[Live Bot INFO] Timeout 15s. Peers in table: %d", len(node.GetPeers()))
	}
}

func creds2Client(c *Credentials) *Credentials {
	cp := *c
	return &cp
}
