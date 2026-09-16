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

	"turnp2p/core/hosts"
	"turnp2p/core/p2p"
	"turnp2p/core/proxy"
	"turnp2p/core/tun"
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
	ObfKey       string   `json:"obfKey"`
	Link         string   `json:"link"`
	FirewallMode string   `json:"firewallMode"`
	SharedPorts  []int    `json:"sharedPorts"`
	StreamsCount int      `json:"streamsCount"`
	NetworkMode  string   `json:"networkMode"` // "userspace" or "tun"
	HostsSync    bool     `json:"hostsSync"`
}

// App struct manages core lifecycle and Wails bindings.
type App struct {
	ctx          context.Context
	turnConn     net.PacketConn
	meshNode     *p2p.MeshNode
	proxyMgr     *proxy.Manager
	hostsMgr     *hosts.Manager
	tunRouter    *tun.Router
	sigClient    *turn.SignalingClient
	networkMode  string // "userspace" (default) or "tun"
	status       ConnectionStatus
	mu           sync.RWMutex
}

// NewApp creates a new App application struct.
func NewApp() *App {
	return &App{
		proxyMgr:    proxy.NewManager(nil),
		hostsMgr:    hosts.NewManager(""),
		networkMode: "userspace",
		status: ConnectionStatus{
			Connected:    false,
			StatusText:   "Disconnected",
			ObfProfile:   "rtpopus3",
			FirewallMode: p2p.FirewallModeWhitelist,
			SharedPorts:  []int{},
			StreamsCount: 10,
			NetworkMode:  "userspace",
			HostsSync:    false,
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

// SetNetworkMode switches between "userspace" and "tun" modes.
func (a *App) SetNetworkMode(mode string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if mode != "userspace" && mode != "tun" {
		mode = "userspace"
	}
	a.networkMode = mode
	a.status.NetworkMode = mode

	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
	}
	return nil
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

	// 1. Resolve TURN credentials via anonymous VK Call link (with 10 min cache)
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

	// 2. Establish Multi-Stream TURN allocation with rtpopus3 obfuscation & auto-replenish maintainer
	bondedPacketConn, err := turn.AllocateMultiStreamClient(context.Background(), creds, obfKey, streamsCount)
	if err != nil {
		a.status.StatusText = fmt.Sprintf("TURN Relay Failed: %v", err)
		if a.ctx != nil {
			wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
		}
		return nil, fmt.Errorf("failed to allocate TURN relay: %w", err)
	}

	bondedPacketConn.SetCountChangeCallback(func(active int, target int) {
		a.mu.Lock()
		if a.status.Connected {
			a.status.StreamsCount = active
			a.status.StatusText = fmt.Sprintf("Connected (%d/%d parallel streams, rtpopus3)", active, target)
			if a.ctx != nil {
				wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
			}
		}
		a.mu.Unlock()
	})

	a.turnConn = bondedPacketConn

	// 3. Initialize and start P2P MeshNode with custom domain support
	node := p2p.NewMeshNode(nickname, customDomain, "")

	node.SetPeerCallback(func(peers []p2p.Peer) {
		// Sync peer domains to OS hosts file
		hostsMap := make(map[string]string)
		for _, p := range peers {
			if p.Domain != "" {
				if a.networkMode == "tun" {
					hostsMap[p.Domain] = p.VirtualIP
				} else {
					hostsMap[p.Domain] = p2p.ToLoopbackIP(p.VirtualIP)
				}
			}
		}
		_ = a.hostsMgr.Sync(hostsMap)

		// In Userspace mode, automatically forward open ports of discovered peers in background
		if a.networkMode != "tun" {
			a.autoSyncProxyRules(peers)
		}

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

	// 4. Start automatic signaling exchange via VK Call WebSocket if available
	if creds.WsEndpoint != "" {
		id, _, _, _ := node.GetInfo()
		sig := turn.NewSignalingClient(creds.WsEndpoint, vkLink, obfKey)
		localInfo := turn.SignalingPeerInfo{
			ID:          id,
			Name:        name,
			RelayAddr:   relayAddrStr,
			VirtualIP:   vIP,
			Domain:      domain,
			SharedPorts: ports,
		}
		sig.Start(context.Background(), localInfo, func(peerRelayAddr string) {
			log.Printf("[App] Discovered peer relay via signaling: %s, connecting...", peerRelayAddr)
			_ = node.ConnectPeer(peerRelayAddr)
		}, func(rawPacket []byte, fromRelay string) {
			fakeAddr, _ := net.ResolveUDPAddr("udp", fromRelay)
			bondedPacketConn.InjectPacket(rawPacket, fakeAddr)
		})
		bondedPacketConn.SetSignalingSender(func(data []byte, targetAddr string) {
			sig.SendFrame(data, targetAddr)
		})
		a.sigClient = sig
	}

	// 5. If TUN mode requested, attempt to create and start TUN Device
	activeMode := a.networkMode
	if activeMode == "tun" {
		tunDev, tunErr := tun.OpenDevice("turnp2p0", vIP)
		if tunErr != nil {
			log.Printf("[App] TUN mode creation failed (%v). Falling back to Userspace mode", tunErr)
			activeMode = "userspace"
		} else {
			router := tun.NewRouter(tunDev, node)
			if err := router.Start(context.Background()); err != nil {
				log.Printf("[App] TUN router start failed (%v). Falling back to Userspace mode", err)
				_ = tunDev.Close()
				activeMode = "userspace"
			} else {
				a.tunRouter = router
				log.Printf("[App] System TUN L3 adapter activated successfully on %s (%s)", tunDev.Name(), vIP)
			}
		}
	}

	initialActive := bondedPacketConn.ActiveCount()

	a.status = ConnectionStatus{
		Connected:    true,
		StatusText:   fmt.Sprintf("Connected (%d/%d parallel streams, rtpopus3)", initialActive, streamsCount),
		VirtualIP:    vIP,
		Domain:       domain,
		NodeName:     name,
		RelayAddr:    relayAddrStr,
		ObfProfile:   "rtpopus3",
		ObfKey:       obfKey,
		Link:         vkLink,
		FirewallMode: mode,
		SharedPorts:  ports,
		StreamsCount: initialActive,
		NetworkMode:  activeMode,
		HostsSync:    true,
	}

	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "status_change", a.status)
	}

	log.Printf("[App] Network joined successfully: %s (%s, %s) in %s mode with %d streams", name, vIP, domain, activeMode, initialActive)
	return &a.status, nil
}

// ConnectPeer manually sends a discovery probe to a peer's relay address.
func (a *App) ConnectPeer(address string) error {
	a.mu.RLock()
	node := a.meshNode
	a.mu.RUnlock()

	if node == nil {
		return fmt.Errorf("mesh node is not connected")
	}

	return node.ConnectPeer(address)
}

// LeaveNetwork disconnects from the mesh network.
func (a *App) LeaveNetwork() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.status.Connected {
		return nil
	}

	if a.sigClient != nil {
		a.sigClient.Stop()
		a.sigClient = nil
	}

	if a.tunRouter != nil {
		_ = a.tunRouter.Stop()
		a.tunRouter = nil
	}

	_ = a.hostsMgr.Clean()

	if a.meshNode != nil {
		a.meshNode.Stop()
		a.meshNode = nil
	}

	if a.turnConn != nil {
		_ = a.turnConn.Close()
		a.turnConn = nil
	}

	a.proxyMgr.Stop()

	a.status = ConnectionStatus{
		Connected:    false,
		StatusText:   "Disconnected",
		ObfProfile:   "rtpopus3",
		FirewallMode: p2p.FirewallModeWhitelist,
		SharedPorts:  []int{},
		StreamsCount: 10,
		NetworkMode:  a.networkMode,
		HostsSync:    false,
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

func (a *App) autoSyncProxyRules(peers []p2p.Peer) {
	currentRules := a.proxyMgr.ListRules()
	existingRuleMap := make(map[string]bool)
	for _, r := range currentRules {
		rIP := r.LocalIP
		if rIP == "" {
			rIP = "127.0.0.1"
		}
		existingRuleMap[fmt.Sprintf("%s:%d", rIP, r.LocalPort)] = true
	}

	for _, p := range peers {
		targetAddr := p.Domain
		if targetAddr == "" {
			targetAddr = p.VirtualIP
		}
		loopbackIP := p2p.ToLoopbackIP(p.VirtualIP)

		for _, port := range p.SharedPorts {
			key := fmt.Sprintf("%s:%d", loopbackIP, port)
			if !existingRuleMap[key] {
				_ = a.proxyMgr.AddRule(proxy.ForwardingRule{
					Name:       fmt.Sprintf("%s :%d", p.Name, port),
					Protocol:   "TCP",
					LocalIP:    loopbackIP,
					LocalPort:  port,
					RemoteIP:   targetAddr,
					RemotePort: port,
				})
			}
		}
	}
}
