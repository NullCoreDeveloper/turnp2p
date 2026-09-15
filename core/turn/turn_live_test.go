package turn

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveVKTurnRelayExchange performs a real-world live exchange through physical VK TURN servers.
// To run: VK_TEST_LINK="https://vk.com/call/join/..." go test -v -run TestLiveVKTurnRelayExchange ./core/turn
func TestLiveVKTurnRelayExchange(t *testing.T) {
	vkLink := os.Getenv("VK_TEST_LINK")
	if vkLink == "" {
		t.Skip("Skipping live VK TURN server test: set VK_TEST_LINK env var to run (e.g. VK_TEST_LINK=\"https://vk.com/call/join/...\")")
		return
	}

	t.Logf("[Live Test] Connecting to VK Call: %s", vkLink)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Fetch credentials (will use cache on subsequent runs for 10 minutes)
	startAuth := time.Now()
	creds, err := FetchVKTurnCredentials(ctx, vkLink)
	if err != nil {
		t.Fatalf("[Live Test] Failed to obtain VK TURN credentials: %v", err)
	}
	t.Logf("[Live Test] Auth took %v. TURN Server: %s, User: %s", time.Since(startAuth), creds.ServerAddr, creds.Username)

	// 2. Allocate Client 1 on real VK TURN server with rtpopus3
	obfKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	client1 := NewClient()
	conn1, err := client1.Connect(ctx, creds, obfKey)
	if err != nil {
		t.Fatalf("[Live Test] Client 1 failed to allocate relay: %v", err)
	}
	defer client1.Disconnect()
	relayAddr1 := client1.GetRelayAddress()
	t.Logf("[Live Test] Client 1 allocated real TURN relay: %s", relayAddr1)

	// 3. Allocate Client 2 on real VK TURN server with rtpopus3
	client2 := NewClient()
	conn2, err := client2.Connect(ctx, creds, obfKey)
	if err != nil {
		t.Fatalf("[Live Test] Client 2 failed to allocate relay: %v", err)
	}
	defer client2.Disconnect()
	relayAddr2 := client2.GetRelayAddress()
	t.Logf("[Live Test] Client 2 allocated real TURN relay: %s", relayAddr2)

	// 4. Send live packet from Client 1 -> Client 2 through the VK TURN relay
	sendPayload := []byte("LIVE_VK_TURN_P2P_PAYLOAD_TEST_42")
	t.Logf("[Live Test] Client 1 -> Client 2 (sending %d bytes through %s)...", len(sendPayload), creds.ServerAddr)

	startPing := time.Now()
	_, err = conn1.WriteTo(sendPayload, relayAddr2)
	if err != nil {
		t.Fatalf("[Live Test] Client 1 WriteTo failed: %v", err)
	}

	// 5. Read on Client 2
	recvBuf := make([]byte, 1024)
	_ = conn2.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, addr, err := conn2.ReadFrom(recvBuf)
	if err != nil {
		t.Fatalf("[Live Test] Client 2 failed to receive packet from TURN relay: %v", err)
	}
	t.Logf("[Live Test] Client 2 received %d bytes from %s: %q", n, addr, string(recvBuf[:n]))

	if string(recvBuf[:n]) != string(sendPayload) {
		t.Fatalf("[Live Test] Payload mismatch: got %q, want %q", string(recvBuf[:n]), string(sendPayload))
	}

	// 6. Client 2 replies back to Client 1
	replyPayload := []byte("LIVE_VK_TURN_P2P_REPLY_OK_99")
	_, err = conn2.WriteTo(replyPayload, relayAddr1)
	if err != nil {
		t.Fatalf("[Live Test] Client 2 reply failed: %v", err)
	}

	_ = conn1.SetReadDeadline(time.Now().Add(10 * time.Second))
	n2, _, err := conn1.ReadFrom(recvBuf)
	if err != nil {
		t.Fatalf("[Live Test] Client 1 failed to receive reply: %v", err)
	}

	rtt := time.Since(startPing)
	t.Logf("[Live Test] Client 1 received reply %q. Full Round-Trip Time through VK TURN: %v", string(recvBuf[:n2]), rtt)

	if string(recvBuf[:n2]) != string(replyPayload) {
		t.Fatalf("[Live Test] Reply mismatch: got %q, want %q", string(recvBuf[:n2]), string(replyPayload))
	}

	t.Logf("[Live Test] SUCCESS! Real-world VK TURN relay packet exchange passed flawlessly (RTT: %v).", rtt)
}
