package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"turnp2p/core/p2p"
	"turnp2p/core/proxy"
	"turnp2p/core/turn"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// ConnectionStatus represents the live network state for the frontend.
type ConnectionStatus struct {
	Connected    bool     `json:"connected"`
	StatusText   string   `json:"statusText"`
	VirtualIP    string   `json:"virtualIp"`
	Domain       string   `json:"domain"`
	NodeName     string   `json:"nodeName"`
	RelayAddr    string   `json:"relayAddr"`
	ObfProfile   string   `json:"obfProfile"`
	Link         string   `json:"link"`
	FirewallMode string   `json:"firewallMode"`
	SharedPorts  []int    `json:"sharedPorts"`
	StreamsCount int      `json:"streamsCount"`
}

// App struct manages core lifecycle and Wails bindings.
type App struct {
	ctx          context.Context
	turnClients  []*turn.PionClient
	turnConn     net.PacketConn
	meshNode     *p2p.MeshNode
	proxyMgr     *proxy.Manager
	status       ConnectionStatus
	mu           sync.RWMutex
}

// NewApp creates a new App application struct.
func NewApp() *App {
	return &App{
		proxyMgr: proxy.NewManager(nil),
		status: ConnectionStatus{
			Connected:    false,
			StatusText:   "Disconnected",
			ObfProfile:   "rtpopus3",
			FirewallMode: p2p.FirewallModeWhitelist,
			SharedPorts:  []int{},
			StreamsCount: 10,
		},
	}
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// GenerateRandomKey produces a 64-character hex key (32 bytes) for rtpopus3 obfuscation.
func (a *App) GenerateRandomKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GetStatus returns the current connection status.
func (a *App) GetStatus() ConnectionStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.status
}

// JoinNetwork connects to the VK TURN infrastructure with configurable parallel streams and joins the P2P mesh.
func (a *App) JoinNetwork(vkLink string, nickname string, customDomain string, obfKey string, streamsCount int) (*ConnectionStatus, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.status.Connected {
		return &a.status, nil
	}

	if streamsCount <= 0 {
		streamsCount = 10
	}

	a.status.StatusText = "Resolving VK Call..."
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
	}

	if obfKey == "" {
		obfKey = a.GenerateRandomKey()
	}

	// 1. Resolve TURN credentials via anonymous VK Call link
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	creds, err := turn.FetchVKTurnCredentials(ctx, vkLink)
	if err != nil {
		a.status.StatusText = fmt.Sprintf("Auth Failed: %v", err)
		if a.ctx != nil {
			wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
		}
		return nil, fmt.Errorf("failed to get TURN credentials: %w", err)
	}

	a.status.StatusText = fmt.Sprintf("Allocating %d parallel TURN streams (rtpopus3)...", streamsCount)
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
	}

	// 2. Establish Multi-Stream TURN allocation with rtpopus3 obfuscation
	bondedPacketConn, clients, err := turn.AllocateMultiStreamClient(context.Background(), creds, obfKey, streamsCount)
	if err != nil {
		a.status.StatusText = fmt.Sprintf("TURN Relay Failed: %v", err)
		if a.ctx != nil {
			wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
		}
		return nil, fmt.Errorf("failed to allocate TURN relay: %w", err)
	}

	a.turnClients = clients
	a.turnConn = bondedPacketConn

	// 3. Initialize and start P2P MeshNode with custom domain support
	node := p2p.NewMeshNode(nickname, customDomain, "")
	node.SetPeerCallback(func(peers []p2p.Peer) {
		if a.ctx != nil {
			wailsRuntime.EventsEmit(a.ctx, "peers_updated", peers)
		}
	})

	if err := node.Start(context.Background(), bondedPacketConn); err != nil {
		_ = bondedPacketConn.Close()
		return nil, fmt.Errorf("failed to start mesh node: %w", err)
	}

	a.meshNode = node
	a.proxyMgr.SetMeshNode(node)

	_, name, vIP, domain := node.GetInfo()
	relayAddrStr := ""
	if addr := bondedPacketConn.LocalAddr(); addr != nil {
		relayAddrStr = addr.String()
	}

	mode, ports := node.GetFirewallConfig()

	a.status = ConnectionStatus{
		Connected:    true,
		StatusText:   fmt.Sprintf("Connected (%d parallel streams, rtpopus3)", len(clients)),
		VirtualIP:    vIP,
		Domain:       domain,
		NodeName:     name,
		RelayAddr:    relayAddrStr,
		ObfProfile:   "rtpopus3",
		Link:         vkLink,
		FirewallMode: mode,
		SharedPorts:  ports,
		StreamsCount: len(clients),
	}

	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
	}

	log.Printf("[App] Network joined successfully: %s (%s, %s) with %d streams", name, vIP, domain, len(clients))
	return &a.status, nil
}

// LeaveNetwork disconnects from the mesh network.
func (a *App) LeaveNetwork() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.status.Connected {
		return nil
	}

	if a.meshNode != nil {
		a.meshNode.Stop()
		a.meshNode = nil
	}

	if a.turnConn != nil {
		_ = a.turnConn.Close()
		a.turnConn = nil
	}

	for _, c := range a.turnClients {
		_ = c.Disconnect()
	}
	a.turnClients = nil

	a.proxyMgr.Stop()

	a.status = ConnectionStatus{
		Connected:    false,
		StatusText:   "Disconnected",
		ObfProfile:   "rtpopus3",
		FirewallMode: p2p.FirewallModeWhitelist,
		SharedPorts:  []int{},
		StreamsCount: 10,
	}

	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
		wailsRuntime.EventsEmit(a.ctx, "peers_updated", []p2p.Peer{})
	}

	return nil
}

// SetFirewallMode updates the inbound firewall policy (whitelist, block_all, allow_all).
func (a *App) SetFirewallMode(mode string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.meshNode != nil {
		a.meshNode.SetFirewallMode(mode)
	}
	a.status.FirewallMode = mode

	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
	}
	return nil
}

// AllowInboundPort adds a port to the inbound firewall whitelist.
func (a *App) AllowInboundPort(port int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.meshNode != nil {
		a.meshNode.AllowPort(port)
		_, ports := a.meshNode.GetFirewallConfig()
		a.status.SharedPorts = ports
	}

	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
	}
	return nil
}

// DisallowInboundPort removes a port from the firewall whitelist.
func (a *App) DisallowInboundPort(port int) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.meshNode != nil {
		a.meshNode.DisallowPort(port)
		_, ports := a.meshNode.GetFirewallConfig()
		a.status.SharedPorts = ports
	}

	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
	}
	return nil
}

// GetPeers returns the list of current active peers.
func (a *App) GetPeers() []p2p.Peer {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if a.meshNode == nil {
		return []p2p.Peer{}
	}
	return a.meshNode.GetPeers()
}

// AddForwardRule registers a new port forward rule.
func (a *App) AddForwardRule(rule proxy.ForwardingRule) error {
	return a.proxyMgr.AddRule(rule)
}

// RemoveForwardRule removes an active port forward rule by ID.
func (a *App) RemoveForwardRule(id string) error {
	return a.proxyMgr.RemoveRule(id)
}

// GetForwardRules returns all active port forward rules.
func (a *App) GetForwardRules() []proxy.ForwardingRule {
	return a.proxyMgr.ListRules()
}
