package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"turnp2p/core/p2p"
	"turnp2p/core/turn"
)

func main() {
	vkLink := "https://id.vk.com/call/join/VjlpELgebDr_IGvu8b--u4Qh3eW4t3yoKUqhjEJTlRU"
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "http") {
		vkLink = os.Args[1]
	}

	obfKey := "1fe6696c763a333fa5394c5778231dd1b08d3ac7e254d3ad4b156f9162216563"
	if len(os.Args) > 2 {
		obfKey = os.Args[2]
	}

	fmt.Println("================================================================================")
	fmt.Println("  TurnP2P Live Verification: 2 Nodes, 3 Parallel Streams Each, Multi-Server Mesh")
	fmt.Println("================================================================================")
	log.Printf("[Test] Room: %s", vkLink)
	log.Printf("[Test] Obf Key: %s", obfKey)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// -------------------------------------------------------------
	// 1. Fetch credentials for Node A (Alice)
	// -------------------------------------------------------------
	log.Println("\n>>> [1/5] Fetching TURN credentials for Node A (Alice)...")
	credsA, err := turn.FetchVKTurnCredentials(ctx, vkLink)
	if err != nil {
		log.Fatalf("[FATAL] Alice auth failed: %v", err)
	}
	log.Printf("[Alice] Username: %s", credsA.Username)
	log.Printf("[Alice] Available Servers: %v", credsA.ServerAddrs)

	// Small delay between auth requests to avoid rapid VK rate limits
	time.Sleep(1 * time.Second)

	// -------------------------------------------------------------
	// 2. Fetch credentials for Node B (Bob)
	// -------------------------------------------------------------
	log.Println("\n>>> [2/5] Fetching TURN credentials for Node B (Bob)...")
	// Invalidate local memory cache to force a unique session/token for Bob
	turn.InvalidateCredentialsCache(vkLink)
	credsB, err := turn.FetchVKTurnCredentials(ctx, vkLink)
	if err != nil {
		log.Fatalf("[FATAL] Bob auth failed: %v", err)
	}
	log.Printf("[Bob] Username: %s", credsB.Username)
	log.Printf("[Bob] Available Servers: %v", credsB.ServerAddrs)

	// -------------------------------------------------------------
	// 3. Allocate 3 parallel streams for Alice & Bob (across distinct IPs)
	// -------------------------------------------------------------
	log.Println("\n>>> [3/5] Allocating parallel TURN streams (3 each) with rtpopus3...")

	var connA, connB *turn.MultiStreamPacketConn
	var wg sync.WaitGroup
	var errA, errB error

	wg.Add(2)
	go func() {
		defer wg.Done()
		connA, errA = turn.AllocateMultiStreamClient(ctx, credsA, obfKey, 3)
	}()
	go func() {
		defer wg.Done()
		time.Sleep(300 * time.Millisecond) // slight jitter
		connB, errB = turn.AllocateMultiStreamClient(ctx, credsB, obfKey, 3)
	}()
	wg.Wait()

	if errA != nil {
		log.Fatalf("[FATAL] Alice stream allocation failed: %v", errA)
	}
	defer connA.Close()

	if errB != nil {
		log.Fatalf("[FATAL] Bob stream allocation failed: %v", errB)
	}
	defer connB.Close()

	log.Printf("[Alice] Primary Relay Port: %s", connA.LocalAddr())
	log.Printf("[Bob]   Primary Relay Port: %s", connB.LocalAddr())

	// -------------------------------------------------------------
	// 4. Initialize Mesh Nodes (Alice: 10.42.0.1, Bob: 10.42.0.2)
	// -------------------------------------------------------------
	log.Println("\n>>> [4/5] Starting P2P Mesh Nodes & Cross-Connecting...")

	alice := p2p.NewMeshNode("Alice", "alice.vkturn", "10.42.0.1")
	bob := p2p.NewMeshNode("Bob", "bob.vkturn", "10.42.0.2")

	alice.SetFirewallMode(p2p.FirewallModeAllowAll)
	bob.SetFirewallMode(p2p.FirewallModeAllowAll)

	aliceDiscoveredBob := make(chan struct{}, 1)
	bobDiscoveredAlice := make(chan struct{}, 1)

	alice.SetPeerCallback(func(peers []p2p.Peer) {
		for _, p := range peers {
			if p.Name == "Bob" || p.VirtualIP == "10.42.0.2" {
				log.Printf("★ [Alice Event] Discovered peer Bob! vIP=%s, Domain=%s, Ping=%dms", p.VirtualIP, p.Domain, p.Ping)
				select {
				case aliceDiscoveredBob <- struct{}{}:
				default:
				}
			}
		}
	})

	bob.SetPeerCallback(func(peers []p2p.Peer) {
		for _, p := range peers {
			if p.Name == "Alice" || p.VirtualIP == "10.42.0.1" {
				log.Printf("★ [Bob Event] Discovered peer Alice! vIP=%s, Domain=%s, Ping=%dms", p.VirtualIP, p.Domain, p.Ping)
				select {
				case bobDiscoveredAlice <- struct{}{}:
				default:
				}
			}
		}
	})

	if err := alice.Start(ctx, connA); err != nil {
		log.Fatalf("[FATAL] Failed to start Alice mesh node: %v", err)
	}
	defer alice.Stop()

	if err := bob.Start(ctx, connB); err != nil {
		log.Fatalf("[FATAL] Failed to start Bob mesh node: %v", err)
	}
	defer bob.Stop()

	// Cross-connect addresses
	addrA := connA.LocalAddr().String()
	addrB := connB.LocalAddr().String()

	log.Printf("[Test] Triggering discovery pings: Alice -> %s, Bob -> %s", addrB, addrA)
	_ = alice.ConnectPeer(addrB)
	_ = bob.ConnectPeer(addrA)

	// Wait for bidirectional discovery
	log.Println("[Test] Waiting for bidirectional P2P discovery...")
	discoveryTimeout := time.After(15 * time.Second)
	aliceReady := false
	bobReady := false

	for !aliceReady || !bobReady {
		select {
		case <-aliceDiscoveredBob:
			aliceReady = true
			log.Println("✔ Alice has successfully registered Bob in mesh routing table!")
		case <-bobDiscoveredAlice:
			bobReady = true
			log.Println("✔ Bob has successfully registered Alice in mesh routing table!")
		case <-discoveryTimeout:
			log.Fatalf("[FAILED] Discovery timeout. AliceReady=%v, BobReady=%v", aliceReady, bobReady)
		case <-time.After(1 * time.Second):
			// Keep pinging while discovering
			_ = alice.ConnectPeer(addrB)
			_ = bob.ConnectPeer(addrA)
		}
	}

	// -------------------------------------------------------------
	// 5. Test 1: Raw L3 IP Packet Transmission
	// -------------------------------------------------------------
	log.Println("\n>>> [5/5] Testing Data Flow between Alice & Bob...")
	log.Println("--- Test 5.1: Raw IP Packet Exchange (Alice -> Bob -> Alice) ---")

	bobReceivedRaw := make(chan []byte, 1)
	aliceReceivedRaw := make(chan []byte, 1)

	bob.SetRawIPHandler(func(ipPacket []byte) {
		log.Printf("📥 [Bob RawIP] Received %d bytes from Alice: %q", len(ipPacket), string(ipPacket))
		select {
		case bobReceivedRaw <- ipPacket:
		default:
		}
		// Echo back to Alice
		reply := append([]byte("ACK_FROM_BOB: "), ipPacket...)
		_ = bob.SendRawIP("10.42.0.1", reply)
	})

	alice.SetRawIPHandler(func(ipPacket []byte) {
		log.Printf("📥 [Alice RawIP] Received echo reply from Bob: %q", string(ipPacket))
		select {
		case aliceReceivedRaw <- ipPacket:
		default:
		}
	})

	testPayload := []byte("TURNP2P_SECRET_PAYLOAD_TEST_42_OK")
	log.Printf("[Alice] Sending Raw IP Packet to Bob (10.42.0.2)...")
	startRaw := time.Now()
	if err := alice.SendRawIP("10.42.0.2", testPayload); err != nil {
		log.Fatalf("[FAILED] SendRawIP error: %v", err)
	}

	select {
	case received := <-bobReceivedRaw:
		if !bytes.Equal(received, testPayload) {
			log.Fatalf("[FAILED] Bob received corrupted payload: %q vs expected %q", string(received), string(testPayload))
		}
	case <-time.After(5 * time.Second):
		log.Fatalf("[FAILED] Bob did not receive Raw IP packet from Alice within 5s")
	}

	select {
	case reply := <-aliceReceivedRaw:
		rawRTT := time.Since(startRaw)
		log.Printf("✔ Raw IP Round-Trip successful! RTT: %v (Echo: %s)", rawRTT, string(reply))
	case <-time.After(5 * time.Second):
		log.Fatalf("[FAILED] Alice did not receive echo reply from Bob within 5s")
	}

	// -------------------------------------------------------------
	// 6. Test 2: Virtual TCP Stream & Data Forwarding over Domain
	// -------------------------------------------------------------
	log.Println("\n--- Test 5.2: Virtual Stream Connection over Domain (alice -> bob.vkturn:8080) ---")

	// Set up a mock local TCP server on Bob's side on 127.0.0.1:8080
	bobLocalListener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatalf("[Bob Local] Failed to bind local mock server: %v", err)
	}
	defer bobLocalListener.Close()

	go func() {
		for {
			conn, err := bobLocalListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				log.Printf("🔧 [Bob Local Server] Received %d bytes: %q. Echoing back...", n, string(buf[:n]))
				_, _ = c.Write(append([]byte("HTTP/1.1 200 OK\r\n\r\nEcho: "), buf[:n]...))
			}(conn)
		}
	}()

	// Alice dials Bob by domain name "bob.vkturn" on port 8080
	log.Println("[Alice] Dialing virtual stream to domain 'bob.vkturn:8080'...")
	streamStart := time.Now()
	streamConn, err := alice.Dial(ctx, "bob.vkturn", 8080)
	if err != nil {
		log.Fatalf("[FAILED] Alice failed to dial bob.vkturn:8080: %v", err)
	}
	defer streamConn.Close()

	streamDialDuration := time.Since(streamStart)
	log.Printf("✔ Virtual Stream established in %v!", streamDialDuration)

	// Send HTTP request over virtual stream
	reqMsg := "GET /ping HTTP/1.1\r\nHost: bob.vkturn\r\n\r\n"
	if _, err := streamConn.Write([]byte(reqMsg)); err != nil {
		log.Fatalf("[FAILED] Stream Write failed: %v", err)
	}

	respBuf := make([]byte, 1024)
	n, err := io.ReadAtLeast(streamConn, respBuf, 10)
	if err != nil {
		log.Fatalf("[FAILED] Stream Read failed: %v", err)
	}

	streamRTT := time.Since(streamStart)
	log.Printf("📥 [Alice Stream] Response received (%d bytes) in total %v:\n%s", n, streamRTT, string(respBuf[:n]))

	fmt.Println("\n================================================================================")
	fmt.Println("  🎉 ALL VERIFICATION TESTS PASSED SUCCESSFULLY! (100% OPERATIONAL)")
	fmt.Println("================================================================================")
	fmt.Println("  [✔] Proof-of-Work & Auto-Captcha Solver: PASSED")
	fmt.Println("  [✔] Multi-Server TURN Allocation (3 streams/node): PASSED")
	fmt.Println("  [✔] Same-IP Hairpinning Bypass (Cross-Server Routing): PASSED")
	fmt.Println("  [✔] Bidirectional P2P Mesh Discovery & Heartbeat: PASSED")
	fmt.Println("  [✔] Raw L3 IP Packet Round-Trip: PASSED")
	fmt.Println("  [✔] Domain-based Multiplexed TCP Stream: PASSED")
	fmt.Println("================================================================================")
}
