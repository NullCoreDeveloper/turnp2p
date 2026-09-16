package turn

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"turnp2p/core/p2p"

	"github.com/pion/turn/v4"
)

// TestP2PEndToEndOverRealTurnServer spins up real in-process TURN servers,
// allocates 2 MultiStreamPacketConn pools (3 streams each, with rtpopus3 obfuscation),
// establishes MeshNode P2P mesh, and tests bidirectional ping, raw IP and TCP virtual streams.
func TestP2PEndToEndOverRealTurnServer(t *testing.T) {
	// 1. Start real in-process TURN server on 127.0.0.1
	udpListener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer udpListener.Close()

	serverAddr := udpListener.LocalAddr().String()

	usersMap := map[string][]byte{
		"testuser": turn.GenerateAuthKey("testuser", "turnp2p.realm", "testpass"),
	}

	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm: "turnp2p.realm",
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			if key, ok := usersMap[username]; ok {
				return key, true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "127.0.0.1",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create turn server: %v", err)
	}
	defer turnServer.Close()

	t.Logf("Real TURN Server running on: %s", serverAddr)

	creds := &Credentials{
		Username:    "testuser",
		Password:    "testpass",
		ServerAddr:  serverAddr,
		ServerAddrs: []string{serverAddr},
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}

	obfKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 2. Allocate 3 streams for Node A (Alice)
	connA, err := AllocateMultiStreamClient(ctx, creds, obfKey, 3)
	if err != nil {
		t.Fatalf("Alice stream allocation failed: %v", err)
	}
	defer connA.Close()

	// 3. Allocate 3 streams for Node B (Bob)
	connB, err := AllocateMultiStreamClient(ctx, creds, obfKey, 3)
	if err != nil {
		t.Fatalf("Bob stream allocation failed: %v", err)
	}
	defer connB.Close()

	t.Logf("Alice Allocated Relay: %s", connA.LocalAddr())
	t.Logf("Bob Allocated Relay: %s", connB.LocalAddr())

	// 4. Start P2P Mesh Nodes
	alice := p2p.NewMeshNode("Alice", "alice.vkturn", "10.42.0.1")
	bob := p2p.NewMeshNode("Bob", "bob.vkturn", "10.42.0.2")

	alice.SetFirewallMode(p2p.FirewallModeAllowAll)
	bob.SetFirewallMode(p2p.FirewallModeAllowAll)

	aliceDiscoveredBob := make(chan struct{}, 1)
	bobDiscoveredAlice := make(chan struct{}, 1)

	alice.SetPeerCallback(func(peers []p2p.Peer) {
		for _, p := range peers {
			if p.VirtualIP == "10.42.0.2" {
				select {
				case aliceDiscoveredBob <- struct{}{}:
				default:
				}
			}
		}
	})

	bob.SetPeerCallback(func(peers []p2p.Peer) {
		for _, p := range peers {
			if p.VirtualIP == "10.42.0.1" {
				select {
				case bobDiscoveredAlice <- struct{}{}:
				default:
				}
			}
		}
	})

	if err := alice.Start(ctx, connA); err != nil {
		t.Fatalf("start Alice: %v", err)
	}
	defer alice.Stop()

	if err := bob.Start(ctx, connB); err != nil {
		t.Fatalf("start Bob: %v", err)
	}
	defer bob.Stop()

	// Connect peers
	_ = alice.ConnectPeer(connB.LocalAddr().String())
	_ = bob.ConnectPeer(connA.LocalAddr().String())

	// Wait for discovery
	select {
	case <-aliceDiscoveredBob:
		t.Logf("✔ Alice discovered Bob over TURN relay!")
	case <-time.After(5 * time.Second):
		t.Fatalf("Alice failed to discover Bob within 5s")
	}

	select {
	case <-bobDiscoveredAlice:
		t.Logf("✔ Bob discovered Alice over TURN relay!")
	case <-time.After(5 * time.Second):
		t.Fatalf("Bob failed to discover Alice within 5s")
	}

	// 5. Test Raw L3 IP packet round-trip
	bobReceivedRaw := make(chan []byte, 1)
	aliceReceivedEcho := make(chan []byte, 1)

	bob.SetRawIPHandler(func(pkt []byte) {
		bobReceivedRaw <- pkt
		_ = bob.SendRawIP("10.42.0.1", append([]byte("ECHO:"), pkt...))
	})

	alice.SetRawIPHandler(func(pkt []byte) {
		aliceReceivedEcho <- pkt
	})

	testPayload := []byte("HELLO_OVER_TURN_P2P_MESH_VERIFIED")
	if err := alice.SendRawIP("10.42.0.2", testPayload); err != nil {
		t.Fatalf("alice SendRawIP: %v", err)
	}

	select {
	case pkt := <-bobReceivedRaw:
		if !bytes.Equal(pkt, testPayload) {
			t.Fatalf("bob received corrupted raw IP: %q", string(pkt))
		}
		t.Logf("✔ Bob received raw IP packet from Alice (%d bytes)", len(pkt))
	case <-time.After(3 * time.Second):
		t.Fatalf("Bob did not receive raw IP packet")
	}

	select {
	case echo := <-aliceReceivedEcho:
		expected := append([]byte("ECHO:"), testPayload...)
		if !bytes.Equal(echo, expected) {
			t.Fatalf("alice received corrupted echo: %q", string(echo))
		}
		t.Logf("✔ Alice received echo reply from Bob over TURN mesh!")
	case <-time.After(3 * time.Second):
		t.Fatalf("Alice did not receive echo reply")
	}

	// 6. Test Virtual TCP Stream & Domain Resolution
	mockTCPListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock tcp: %v", err)
	}
	defer mockTCPListener.Close()

	mockPort := mockTCPListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := mockTCPListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				_, _ = conn.Write(append([]byte("PONG:"), buf[:n]...))
			}(c)
		}
	}()

	streamConn, err := alice.Dial(ctx, "bob.vkturn", mockPort)
	if err != nil {
		t.Fatalf("alice failed to dial bob.vkturn:%d: %v", mockPort, err)
	}
	defer streamConn.Close()

	pingMsg := []byte("PING_OVER_VIRTUAL_STREAM_12345")
	if _, err := streamConn.Write(pingMsg); err != nil {
		t.Fatalf("stream write: %v", err)
	}

	respBuf := make([]byte, 1024)
	n, err := io.ReadAtLeast(streamConn, respBuf, 5)
	if err != nil {
		t.Fatalf("stream read: %v", err)
	}

	t.Logf("✔ Virtual TCP stream response over domain 'bob.vkturn': %q", string(respBuf[:n]))

	if !bytes.Contains(respBuf[:n], pingMsg) {
		t.Fatalf("stream reply mismatch: %q", string(respBuf[:n]))
	}

	t.Log("🎉 COMPLETE P2P END-TO-END VERIFICATION OVER REAL TURN SERVER PASSED!")
}
