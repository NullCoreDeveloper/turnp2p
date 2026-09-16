package p2p

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Frame types for the P2P overlay protocol
const (
	FrameHeartbeat  byte = 0x01
	FrameConnect    byte = 0x02
	FrameConnectAck byte = 0x03
	FrameData       byte = 0x04
	FrameClose      byte = 0x05
	FrameRawIP      byte = 0x06
)

// Firewall Modes
const (
	FirewallModeWhitelist = "whitelist" // Only allow explicitly shared ports (Default)
	FirewallModeBlockAll  = "block_all" // Reject all incoming connections
	FirewallModeAllowAll  = "allow_all" // Allow all incoming connections
)

var (
	ErrPeerNotFound      = errors.New("peer with specified virtual IP or domain not found")
	ErrConnTimeout       = errors.New("connection to peer timed out")
	ErrNodeClosed        = errors.New("p2p node is closed")
	ErrFirewallBlocked   = errors.New("inbound connection rejected by peer firewall")
	domainSanitizeRegex  = regexp.MustCompile(`[^a-zA-Z0-9\-_.]`)
)

// Peer represents a discovered node in the mesh network.
type Peer struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	VirtualIP   string    `json:"virtualIp"`
	Domain      string    `json:"domain"`
	RelayAddr   string    `json:"relayAddr"`
	SharedPorts []int     `json:"sharedPorts"`
	Ping        int       `json:"ping"`
	LastSeen    time.Time `json:"lastSeen"`
}

// HeartbeatPayload is broadcasted periodically over the TURN relay.
type HeartbeatPayload struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	VirtualIP   string `json:"virtualIp"`
	Domain      string `json:"domain"`
	SharedPorts []int  `json:"sharedPorts"`
	Timestamp   int64  `json:"timestamp"`
}

// FirewallConfig holds inbound traffic control rules.
type FirewallConfig struct {
	Mode         string      `json:"mode"`
	AllowedPorts map[int]bool `json:"allowedPorts"`
}

// MeshNode manages peer discovery, virtual IP & domain routing, firewall, and multiplexed streams over TURN.
type MeshNode struct {
	id          string
	name        string
	virtualIP   string
	domain      string
	packetConn  net.PacketConn
	relayAddr   net.Addr
	peers       map[string]*Peer       // key: virtualIP
	peersByID   map[string]*Peer       // key: peerID
	peersByDom  map[string]*Peer       // key: domain (lowercase)
	peerAddrs   map[string]net.Addr    // key: peerID -> remote relay net.Addr
	listeners   map[int]net.Listener   // key: port -> virtual listener
	streams     map[uint32]*VirtualStream
	streamSeq   atomic.Uint32
	firewall    FirewallConfig
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.RWMutex
	running     atomic.Bool
	onPeerEvent func(peers []Peer)
	onRawIP     func(ipPacket []byte)
}

// SanitizeDomain cleans up user custom domain names.
func SanitizeDomain(input string) string {
	cleaned := domainSanitizeRegex.ReplaceAllString(strings.TrimSpace(input), "")
	cleaned = strings.ToLower(cleaned)
	if cleaned == "" {
		return ""
	}
	if !strings.HasSuffix(cleaned, ".vkturn") {
		cleaned = cleaned + ".vkturn"
	}
	return cleaned
}

// ToLoopbackIP converts a mesh virtual IP (e.g. 10.42.X.Y) into a unique local loopback IP (127.0.X.Y).
// This prevents port collisions between different peers in Userspace mode.
func ToLoopbackIP(virtualIP string) string {
	parts := strings.Split(strings.TrimSpace(virtualIP), ".")
	if len(parts) == 4 {
		return fmt.Sprintf("127.0.%s.%s", parts[2], parts[3])
	}
	return "127.0.0.1"
}

// NewMeshNode creates a new P2P mesh node with an assigned virtual IP, custom domain, and default secure firewall.
func NewMeshNode(name string, customDomain string, virtualIP string) *MeshNode {
	if name == "" {
		name = "Node-" + uuid.New().String()[:6]
	}
	if virtualIP == "" {
		b := make([]byte, 2)
		rand.Read(b)
		virtualIP = fmt.Sprintf("10.42.%d.%d", b[0], b[1])
	}

	var domain string
	if customDomain != "" {
		domain = SanitizeDomain(customDomain)
	} else {
		domain = SanitizeDomain(name)
	}

	return &MeshNode{
		id:         uuid.New().String(),
		name:       name,
		virtualIP:  virtualIP,
		domain:     domain,
		peers:      make(map[string]*Peer),
		peersByID:  make(map[string]*Peer),
		peersByDom: make(map[string]*Peer),
		peerAddrs:  make(map[string]net.Addr),
		listeners:  make(map[int]net.Listener),
		streams:    make(map[uint32]*VirtualStream),
		firewall: FirewallConfig{
			Mode:         FirewallModeWhitelist,
			AllowedPorts: make(map[int]bool),
		},
	}
}

// SetCustomDomain updates the local domain name advertised to the network.
func (n *MeshNode) SetCustomDomain(domain string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.domain = SanitizeDomain(domain)
}

// SetFirewallMode updates inbound firewall policy.
func (n *MeshNode) SetFirewallMode(mode string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.firewall.Mode = mode
}

// AllowPort adds a local port to the inbound firewall whitelist.
func (n *MeshNode) AllowPort(port int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.firewall.AllowedPorts[port] = true
}

// DisallowPort removes a local port from the firewall whitelist.
func (n *MeshNode) DisallowPort(port int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.firewall.AllowedPorts, port)
}

// GetFirewallConfig returns current firewall settings.
func (n *MeshNode) GetFirewallConfig() (mode string, allowedPorts []int) {
	n.mu.RLock()
	defer n.mu.RUnlock()

	ports := make([]int, 0, len(n.firewall.AllowedPorts))
	for p := range n.firewall.AllowedPorts {
		ports = append(ports, p)
	}
	return n.firewall.Mode, ports
}

// SetPeerCallback sets the handler invoked when peers join/leave/update.
func (n *MeshNode) SetPeerCallback(cb func(peers []Peer)) {
	n.mu.Lock()
	n.onPeerEvent = cb
	n.mu.Unlock()
}

// SetRawIPHandler sets the handler invoked when raw L3 IP packets arrive over the mesh.
func (n *MeshNode) SetRawIPHandler(cb func(ipPacket []byte)) {
	n.mu.Lock()
	n.onRawIP = cb
	n.mu.Unlock()
}

// SendRawIP routes an IPv4 packet to the destination virtual IP or domain.
func (n *MeshNode) SendRawIP(targetVirtualIP string, ipPacket []byte) error {
	if !n.running.Load() {
		return ErrNodeClosed
	}

	n.mu.RLock()
	peer, exists := n.peers[targetVirtualIP]
	if !exists {
		peer, exists = n.peersByDom[strings.ToLower(targetVirtualIP)]
	}
	if !exists {
		n.mu.RUnlock()
		return fmt.Errorf("%w: %s", ErrPeerNotFound, targetVirtualIP)
	}
	peerAddr := n.peerAddrs[peer.ID]
	n.mu.RUnlock()

	frame := make([]byte, 1+len(ipPacket))
	frame[0] = FrameRawIP
	copy(frame[1:], ipPacket)

	_, err := n.packetConn.WriteTo(frame, peerAddr)
	return err
}

// Start binds the node to the obfuscated TURN packet connection and begins heartbeat discovery.
func (n *MeshNode) Start(ctx context.Context, conn net.PacketConn) error {
	n.mu.Lock()
	if n.running.Load() {
		n.mu.Unlock()
		return errors.New("node already running")
	}

	n.packetConn = conn
	n.relayAddr = conn.LocalAddr()
	n.ctx, n.cancel = context.WithCancel(ctx)
	n.running.Store(true)
	n.mu.Unlock()

	go n.readLoop()
	go n.heartbeatLoop()
	go n.cleanupLoop()

	return nil
}

// Stop gracefully shuts down all streams and stops heartbeat loops.
func (n *MeshNode) Stop() error {
	if !n.running.Swap(false) {
		return nil
	}

	if n.cancel != nil {
		n.cancel()
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	for _, stream := range n.streams {
		stream.Close()
	}
	n.streams = make(map[uint32]*VirtualStream)

	return nil
}

// GetInfo returns local node identification.
func (n *MeshNode) GetInfo() (id, name, virtualIP, domain string) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.id, n.name, n.virtualIP, n.domain
}

// GetPeers returns a slice of currently active peers in the mesh.
func (n *MeshNode) GetPeers() []Peer {
	n.mu.RLock()
	defer n.mu.RUnlock()

	res := make([]Peer, 0, len(n.peers))
	for _, p := range n.peers {
		res = append(res, *p)
	}
	return res
}

// readLoop listens for incoming frames over the TURN obfuscated connection.
func (n *MeshNode) readLoop() {
	buf := make([]byte, 4096)
	for n.running.Load() {
		readBytes, addr, err := n.packetConn.ReadFrom(buf)
		if err != nil {
			if !n.running.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		if readBytes < 1 {
			continue
		}

		frameType := buf[0]
		payload := buf[1:readBytes]

		switch frameType {
		case FrameHeartbeat:
			n.handleHeartbeat(payload, addr)
		case FrameConnect:
			n.handleConnect(payload, addr)
		case FrameConnectAck:
			n.handleConnectAck(payload)
		case FrameData:
			n.handleData(payload)
		case FrameClose:
			n.handleClose(payload)
		case FrameRawIP:
			n.mu.RLock()
			cb := n.onRawIP
			n.mu.RUnlock()
			if cb != nil {
				cb(payload)
			}
		}
	}
}

func (n *MeshNode) handleHeartbeat(payload []byte, addr net.Addr) {
	var hb HeartbeatPayload
	if err := json.Unmarshal(payload, &hb); err != nil {
		return
	}

	// Ignore self
	if hb.ID == n.id {
		return
	}

	n.mu.Lock()
	defer n.mu.Unlock()

	now := time.Now()
	ping := int(time.Since(time.UnixMilli(hb.Timestamp)).Milliseconds())
	if ping < 0 {
		ping = 0
	}

	peer, exists := n.peersByID[hb.ID]
	if !exists {
		peer = &Peer{
			ID:          hb.ID,
			Name:        hb.Name,
			VirtualIP:   hb.VirtualIP,
			Domain:      hb.Domain,
			SharedPorts: hb.SharedPorts,
			RelayAddr:   addr.String(),
			Ping:        ping,
			LastSeen:    now,
		}
		n.peersByID[hb.ID] = peer
		n.peers[hb.VirtualIP] = peer
		n.peersByDom[strings.ToLower(hb.Domain)] = peer
		n.peerAddrs[hb.ID] = addr

		log.Printf("[P2P Mesh] Discovered peer: %s (%s, %s) at %s", hb.Name, hb.VirtualIP, hb.Domain, addr.String())

		// Mutual handshake: immediately send our heartbeat back so the other peer discovers us too!
		go n.PingAddress(addr)
	} else {
		// Clean old domain key if changed
		if peer.Domain != hb.Domain {
			delete(n.peersByDom, strings.ToLower(peer.Domain))
			peer.Domain = hb.Domain
			n.peersByDom[strings.ToLower(hb.Domain)] = peer
		}
		peer.Ping = ping
		peer.LastSeen = now
		peer.RelayAddr = addr.String()
		peer.SharedPorts = hb.SharedPorts
		n.peerAddrs[hb.ID] = addr
	}

	if n.onPeerEvent != nil {
		go n.notifyPeersUpdated()
	}
}

func (n *MeshNode) notifyPeersUpdated() {
	peers := n.GetPeers()
	n.mu.RLock()
	cb := n.onPeerEvent
	n.mu.RUnlock()
	if cb != nil {
		cb(peers)
	}
}

// PingAddress sends a heartbeat ping directly to target network address.
func (n *MeshNode) PingAddress(addr net.Addr) error {
	if n.packetConn == nil {
		return errors.New("packet conn not initialized")
	}

	n.mu.RLock()
	allowedPorts := make([]int, 0, len(n.firewall.AllowedPorts))
	for p := range n.firewall.AllowedPorts {
		allowedPorts = append(allowedPorts, p)
	}
	hb := HeartbeatPayload{
		ID:          n.id,
		Name:        n.name,
		VirtualIP:   n.virtualIP,
		Domain:      n.domain,
		SharedPorts: allowedPorts,
		Timestamp:   time.Now().UnixMilli(),
	}
	n.mu.RUnlock()

	data, err := json.Marshal(hb)
	if err != nil {
		return err
	}

	frame := append([]byte{FrameHeartbeat}, data...)
	var lastErr error
	for i := 0; i < 2; i++ {
		_, lastErr = n.packetConn.WriteTo(frame, addr)
		if i == 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return lastErr
}

// ConnectPeer resolves a remote address string and sends continuous discovery pings.
func (n *MeshNode) ConnectPeer(addrStr string) error {
	addrStr = strings.TrimSpace(addrStr)
	udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
	if err != nil {
		return fmt.Errorf("invalid peer address: %w", err)
	}

	// Send an initial ping immediately
	err = n.PingAddress(udpAddr)

	// Send periodic burst in background for 5 seconds to punch through stateful TURN allocations
	go func() {
		for i := 0; i < 8; i++ {
			time.Sleep(400 * time.Millisecond)
			if !n.running.Load() {
				return
			}
			_ = n.PingAddress(udpAddr)
		}
	}()

	return err
}

// heartbeatLoop sends periodic discovery announcements to known peers.
func (n *MeshNode) heartbeatLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.mu.RLock()
			addrs := make([]net.Addr, 0, len(n.peerAddrs))
			for _, addr := range n.peerAddrs {
				addrs = append(addrs, addr)
			}
			n.mu.RUnlock()

			for _, addr := range addrs {
				_ = n.PingAddress(addr)
			}
		}
	}
}


// cleanupLoop removes peers that stopped responding.
func (n *MeshNode) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			n.mu.Lock()
			now := time.Now()
			changed := false
			for id, peer := range n.peersByID {
				if now.Sub(peer.LastSeen) > 15*time.Second {
					delete(n.peers, peer.VirtualIP)
					delete(n.peersByDom, strings.ToLower(peer.Domain))
					delete(n.peersByID, id)
					delete(n.peerAddrs, id)
					changed = true
					log.Printf("[P2P Mesh] Peer timed out: %s (%s)", peer.Name, peer.VirtualIP)
				}
			}
			n.mu.Unlock()

			if changed {
				n.notifyPeersUpdated()
			}
		}
	}
}

// Dial creates a virtual stream connection to target virtual IP or domain.
func (n *MeshNode) Dial(ctx context.Context, targetAddress string, targetPort int) (net.Conn, error) {
	if !n.running.Load() {
		return nil, ErrNodeClosed
	}

	targetAddress = strings.TrimSpace(targetAddress)

	n.mu.RLock()
	// Resolve by Virtual IP or Domain
	peer, exists := n.peers[targetAddress]
	if !exists {
		peer, exists = n.peersByDom[strings.ToLower(targetAddress)]
		if !exists && !strings.HasSuffix(targetAddress, ".vkturn") {
			peer, exists = n.peersByDom[strings.ToLower(targetAddress+".vkturn")]
		}
	}
	if !exists {
		n.mu.RUnlock()
		return nil, fmt.Errorf("%w: %s", ErrPeerNotFound, targetAddress)
	}
	peerAddr := n.peerAddrs[peer.ID]
	n.mu.RUnlock()

	streamID := n.streamSeq.Add(1)
	stream := newVirtualStream(streamID, n, peerAddr)

	n.mu.Lock()
	n.streams[streamID] = stream
	n.mu.Unlock()

	// Send FrameConnect: [FrameConnect(1b) | streamID(4b) | targetPort(2b)]
	buf := make([]byte, 7)
	buf[0] = FrameConnect
	binary.BigEndian.PutUint32(buf[1:5], streamID)
	binary.BigEndian.PutUint16(buf[5:7], uint16(targetPort))

	if _, err := n.packetConn.WriteTo(buf, peerAddr); err != nil {
		stream.Close()
		return nil, fmt.Errorf("failed to send connect frame: %w", err)
	}

	select {
	case <-stream.connected:
		return stream, nil
	case <-ctx.Done():
		stream.Close()
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		stream.Close()
		return nil, ErrConnTimeout
	}
}

func (n *MeshNode) handleConnect(payload []byte, addr net.Addr) {
	if len(payload) < 6 {
		return
	}
	streamID := binary.BigEndian.Uint32(payload[0:4])
	port := int(binary.BigEndian.Uint16(payload[4:6]))

	// 1. Check Firewall Policy!
	n.mu.RLock()
	firewallMode := n.firewall.Mode
	isAllowed := false

	switch firewallMode {
	case FirewallModeAllowAll:
		isAllowed = true
	case FirewallModeBlockAll:
		isAllowed = false
	case FirewallModeWhitelist:
		isAllowed = n.firewall.AllowedPorts[port]
	}
	n.mu.RUnlock()

	if !isAllowed {
		log.Printf("[Firewall] Rejected inbound connection from %s to port %d (Policy: %s)", addr.String(), port, firewallMode)
		// Send FrameClose immediately
		closeBuf := make([]byte, 5)
		closeBuf[0] = FrameClose
		binary.BigEndian.PutUint32(closeBuf[1:5], streamID)
		n.packetConn.WriteTo(closeBuf, addr)
		return
	}

	// 2. Accept connection
	ackBuf := make([]byte, 5)
	ackBuf[0] = FrameConnectAck
	binary.BigEndian.PutUint32(ackBuf[1:5], streamID)
	n.packetConn.WriteTo(ackBuf, addr)

	stream := newVirtualStream(streamID, n, addr)
	close(stream.connected)

	n.mu.Lock()
	n.streams[streamID] = stream
	listener, hasListener := n.listeners[port]
	n.mu.Unlock()

	if hasListener {
		if vListener, ok := listener.(*VirtualListener); ok {
			vListener.acceptChan <- stream
		}
	} else {
		// If no internal listener registered, route to local localhost:port
		go n.forwardToLocalPort(stream, port)
	}
}

// forwardToLocalPort connects incoming virtual streams to the local machine's service.
func (n *MeshNode) forwardToLocalPort(stream *VirtualStream, port int) {
	defer stream.Close()

	localConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		log.Printf("[MeshNode] Failed to connect to local port %d: %v", port, err)
		return
	}
	defer localConn.Close()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(localConn, stream)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(stream, localConn)
		done <- struct{}{}
	}()

	<-done
	// Flush window to let outgoing response frames transit the network before closing stream
	time.Sleep(100 * time.Millisecond)
}

func (n *MeshNode) handleConnectAck(payload []byte) {
	if len(payload) < 4 {
		return
	}
	streamID := binary.BigEndian.Uint32(payload[0:4])

	n.mu.RLock()
	stream, exists := n.streams[streamID]
	n.mu.RUnlock()

	if exists {
		select {
		case <-stream.connected:
		default:
			close(stream.connected)
		}
	}
}

func (n *MeshNode) handleData(payload []byte) {
	if len(payload) < 4 {
		return
	}
	streamID := binary.BigEndian.Uint32(payload[0:4])
	data := payload[4:]

	n.mu.RLock()
	stream, exists := n.streams[streamID]
	n.mu.RUnlock()

	if exists {
		stream.incomingData(data)
	}
}

func (n *MeshNode) handleClose(payload []byte) {
	if len(payload) < 4 {
		return
	}
	streamID := binary.BigEndian.Uint32(payload[0:4])

	n.mu.RLock()
	stream, exists := n.streams[streamID]
	n.mu.RUnlock()

	if exists {
		stream.closeRemote()
		// Retain stream briefly in map to allow any late arriving FrameData to be buffered
		go func() {
			time.Sleep(2 * time.Second)
			n.mu.Lock()
			delete(n.streams, streamID)
			n.mu.Unlock()
		}()
	}
}

// VirtualStream implements net.Conn for multiplexed P2P data flow.
type VirtualStream struct {
	id        uint32
	node      *MeshNode
	peerAddr  net.Addr
	connected chan struct{}

	mu           sync.Mutex
	cond         *sync.Cond
	buffer       [][]byte
	remoteClosed bool
	localClosed  bool
	readDeadline time.Time
	timer        *time.Timer
}

func newVirtualStream(id uint32, node *MeshNode, peerAddr net.Addr) *VirtualStream {
	s := &VirtualStream{
		id:        id,
		node:      node,
		peerAddr:  peerAddr,
		connected: make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *VirtualStream) incomingData(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.localClosed {
		return
	}
	b := make([]byte, len(data))
	copy(b, data)
	s.buffer = append(s.buffer, b)
	s.cond.Signal()
}

func (s *VirtualStream) closeRemote() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.remoteClosed {
		return
	}
	s.remoteClosed = true
	s.cond.Broadcast()
}

func (s *VirtualStream) Read(b []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for len(s.buffer) == 0 {
		if s.localClosed {
			return 0, io.ErrClosedPipe
		}
		if s.remoteClosed {
			return 0, io.EOF
		}
		if !s.readDeadline.IsZero() && time.Now().After(s.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		s.cond.Wait()
	}

	chunk := s.buffer[0]
	n = copy(b, chunk)
	if n < len(chunk) {
		s.buffer[0] = chunk[n:]
	} else {
		s.buffer = s.buffer[1:]
	}
	return n, nil
}

func (s *VirtualStream) Write(b []byte) (n int, err error) {
	s.mu.Lock()
	if s.localClosed {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	s.mu.Unlock()

	frame := make([]byte, 5+len(b))
	frame[0] = FrameData
	binary.BigEndian.PutUint32(frame[1:5], s.id)
	copy(frame[5:], b)

	_, err = s.node.packetConn.WriteTo(frame, s.peerAddr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *VirtualStream) Close() error {
	s.mu.Lock()
	if s.localClosed {
		s.mu.Unlock()
		return nil
	}
	s.localClosed = true
	if s.timer != nil {
		s.timer.Stop()
	}
	s.cond.Broadcast()
	s.mu.Unlock()

	frame := make([]byte, 5)
	frame[0] = FrameClose
	binary.BigEndian.PutUint32(frame[1:5], s.id)
	s.node.packetConn.WriteTo(frame, s.peerAddr)

	go func() {
		time.Sleep(2 * time.Second)
		s.node.mu.Lock()
		delete(s.node.streams, s.id)
		s.node.mu.Unlock()
	}()

	return nil
}

func (s *VirtualStream) LocalAddr() net.Addr                { return s.node.relayAddr }
func (s *VirtualStream) RemoteAddr() net.Addr               { return s.peerAddr }
func (s *VirtualStream) SetDeadline(t time.Time) error      { return s.SetReadDeadline(t) }
func (s *VirtualStream) SetWriteDeadline(t time.Time) error { return nil }

func (s *VirtualStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if !t.IsZero() {
		dur := time.Until(t)
		if dur <= 0 {
			s.cond.Broadcast()
			return nil
		}
		s.timer = time.AfterFunc(dur, func() {
			s.mu.Lock()
			s.cond.Broadcast()
			s.mu.Unlock()
		})
	}
	return nil
}

// VirtualListener listens for virtual streams incoming to a specific port.
type VirtualListener struct {
	port       int
	node       *MeshNode
	acceptChan chan net.Conn
	closed     atomic.Bool
}

func (l *VirtualListener) Accept() (net.Conn, error) {
	conn, ok := <-l.acceptChan
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *VirtualListener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	l.node.mu.Lock()
	delete(l.node.listeners, l.port)
	l.node.mu.Unlock()
	close(l.acceptChan)
	return nil
}

func (l *VirtualListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(l.node.virtualIP), Port: l.port}
}
