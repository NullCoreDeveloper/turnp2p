package turn

import (
	"context"
	"testing"
	"time"

	"turnp2p/core/p2p"
)

func TestLiveProbeTargetRelay(t *testing.T) {
	vkLink := "https://vk.com/call/join/VjlpELgebDr_IGvu8b--u4Qh3eW4t3yoKUqhjEJTlRU"
	obfKey := "1fe6696c763a333fa5394c5778231dd1b08d3ac7e254d3ad4b156f9162216563"
	targetRelay := "91.231.135.87:53350"

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	t.Logf("[Probe] Fetching VK credentials...")
	creds, err := FetchVKTurnCredentials(ctx, vkLink)
	if err != nil {
		t.Fatalf("Failed credentials: %v", err)
	}

	t.Logf("[Probe] Connecting to TURN...")
	client := NewClient()
	conn, err := client.Connect(ctx, creds, obfKey)
	if err != nil {
		t.Fatalf("Failed TURN connect: %v", err)
	}
	defer client.Disconnect()

	myRelay := conn.LocalAddr().String()
	t.Logf("[Probe] Tester Relay: %s", myRelay)

	node := p2p.NewMeshNode("ProbeTester", "probe.vkturn", "")
	peerFound := make(chan p2p.Peer, 5)

	node.SetPeerCallback(func(peers []p2p.Peer) {
		for _, p := range peers {
			t.Logf("[PEER FOUND!] Name=%s, IP=%s, Domain=%s, Ping=%dms, Ports=%v",
				p.Name, p.VirtualIP, p.Domain, p.Ping, p.SharedPorts)
			peerFound <- p
		}
	})

	if err := node.Start(context.Background(), conn); err != nil {
		t.Fatalf("Failed node start: %v", err)
	}
	defer node.Stop()

	t.Logf("[Probe] Sending discovery probes to user relay: %s...", targetRelay)
	_ = node.ConnectPeer(targetRelay)

	select {
	case p := <-peerFound:
		t.Logf("[SUCCESS!] Found your active client in the room: %s (%s, %s)", p.Name, p.Domain, p.VirtualIP)
	case <-time.After(12 * time.Second):
		t.Logf("[INFO] Probe complete. If your client is still on, check if relay %s is still allocated.", targetRelay)
	}
}

func creds2Client(c *Credentials) *Credentials {
	cp := *c
	return &cp
}
