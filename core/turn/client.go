package turn

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"turnp2p/core/obf"

	"github.com/pion/turn/v4"
)

// Config contains parameters for connecting to the TURN server.
type Config struct {
	VKCallLink string
	ServerAddr string
	Username   string
	Password   string
	ObfProfile string
	ObfKey     string
	UseUDP     bool
}

// Client defines the interface for the TURN relay manager.
type Client interface {
	ResolveCredentials(ctx context.Context, link string) (*Credentials, error)
	Connect(ctx context.Context, creds *Credentials, obfKey string) (net.PacketConn, error)
	Disconnect() error
	GetRelayAddress() net.Addr
}

// PionClient is the production TURN client implementation.
type PionClient struct {
	client     *turn.Client
	relayConn  net.PacketConn
	rawConn    net.PacketConn
	relayAddr  net.Addr
	obfuscator obf.Obfuscator
	mu         sync.RWMutex
	closed     bool
}

// NewClient creates a new PionClient.
func NewClient() *PionClient {
	return &PionClient{}
}

// ResolveCredentials fetches anonymous TURN credentials from VK Call link.
func (c *PionClient) ResolveCredentials(ctx context.Context, link string) (*Credentials, error) {
	return FetchVKTurnCredentials(ctx, link)
}

// Connect establishes a TURN relay allocation and wraps it with rtpopus3 obfuscation.
func (c *PionClient) Connect(ctx context.Context, creds *Credentials, obfKey string) (net.PacketConn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	serverAddr := creds.ServerAddr
	if !strings.Contains(serverAddr, ":") {
		serverAddr = serverAddr + ":3478"
	}

	// 1. Resolve TURN server UDP address
	turnUDPAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve TURN server address %s: %w", serverAddr, err)
	}

	// 2. Open local UDP socket for TURN communication
	localConn, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen on local UDP port: %w", err)
	}
	c.rawConn = localConn

	// 3. Create Pion TURN client
	clientConfig := &turn.ClientConfig{
		STUNServerAddr: turnUDPAddr.String(),
		TURNServerAddr: turnUDPAddr.String(),
		Conn:           localConn,
		Username:       creds.Username,
		Password:       creds.Password,
		RTO:            time.Second * 3,
	}

	turnClient, err := turn.NewClient(clientConfig)
	if err != nil {
		localConn.Close()
		return nil, fmt.Errorf("failed to create turn client: %w", err)
	}
	c.client = turnClient

	// Start STUN/TURN listener loop
	if err := turnClient.Listen(); err != nil {
		turnClient.Close()
		localConn.Close()
		return nil, fmt.Errorf("failed to start turn listener: %w", err)
	}

	// 4. Allocate TURN relay
	relayConn, err := turnClient.Allocate()
	if err != nil {
		turnClient.Close()
		localConn.Close()
		return nil, fmt.Errorf("failed to allocate TURN relay: %w", err)
	}

	c.relayAddr = relayConn.LocalAddr()

	// 5. Initialize rtpopus3 obfuscator
	obfuscator, err := obf.NewRTPOpus3(obfKey)
	if err != nil {
		relayConn.Close()
		turnClient.Close()
		localConn.Close()
		return nil, fmt.Errorf("failed to initialize rtpopus3 obfuscator: %w", err)
	}
	c.obfuscator = obfuscator

	// 6. Wrap relay connection with ObfuscatedPacketConn
	obfConn := obf.NewObfuscatedPacketConn(relayConn, obfuscator)
	c.relayConn = obfConn

	return obfConn, nil
}

// Disconnect cleans up all TURN relay allocations and sockets.
func (c *PionClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true

	var lastErr error
	if c.relayConn != nil {
		if err := c.relayConn.Close(); err != nil {
			lastErr = err
		}
		c.relayConn = nil
	}

	if c.client != nil {
		c.client.Close()
		c.client = nil
	}

	if c.rawConn != nil {
		if err := c.rawConn.Close(); err != nil {
			lastErr = err
		}
		c.rawConn = nil
	}

	return lastErr
}

// GetRelayAddress returns the allocated TURN relay address.
func (c *PionClient) GetRelayAddress() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.relayAddr
}
