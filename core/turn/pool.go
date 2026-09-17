package turn

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type streamHolder struct {
	id     int
	conn   net.PacketConn
	client *PionClient
}

// MultiStreamPacketConn bonds multiple parallel TURN relay connections into a single high-throughput PacketConn
// with automatic background health checks and dynamic stream replenishment.
type MultiStreamPacketConn struct {
	streams       []*streamHolder
	targetCount   int
	creds         *Credentials
	obfKey        string
	roundRobin    atomic.Uint64
	readChan      chan packetResult
	closed        atomic.Bool
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.RWMutex
	wakeChan      chan struct{}
	onCountChange func(active int, target int)
	sigSender     func(data []byte, targetAddr string)
	streamIDSeq   atomic.Int32
	permittedIPs  map[string]net.IP
}

type packetResult struct {
	data []byte
	addr net.Addr
	err  error
}

// NewMultiStreamPacketConn creates a bonded packet connection with automatic stream maintainer.
func NewMultiStreamPacketConn(ctx context.Context, initialStreams []*streamHolder, creds *Credentials, obfKey string, targetCount int) *MultiStreamPacketConn {
	mctx, cancel := context.WithCancel(ctx)
	mpc := &MultiStreamPacketConn{
		streams:      make([]*streamHolder, 0, targetCount),
		targetCount:  targetCount,
		creds:        creds,
		obfKey:       obfKey,
		readChan:     make(chan packetResult, 1024),
		wakeChan:     make(chan struct{}, 16),
		ctx:          mctx,
		cancel:       cancel,
		permittedIPs: make(map[string]net.IP),
	}
	mpc.streamIDSeq.Store(int32(len(initialStreams)))

	for _, s := range initialStreams {
		mpc.addStreamInternal(s)
	}

	go mpc.maintainerLoop()

	return mpc
}

// SetCountChangeCallback sets a callback triggered whenever the number of active streams changes.
func (m *MultiStreamPacketConn) SetCountChangeCallback(cb func(active int, target int)) {
	m.mu.Lock()
	m.onCountChange = cb
	m.mu.Unlock()
}

func (m *MultiStreamPacketConn) addStreamInternal(holder *streamHolder) {
	m.streams = append(m.streams, holder)
	go m.readWorker(holder)
}

// AddStream dynamically adds a newly allocated TURN stream into the live pool.
func (m *MultiStreamPacketConn) AddStream(client *PionClient, conn net.PacketConn) {
	if m.closed.Load() {
		_ = conn.Close()
		_ = client.Disconnect()
		return
	}

	m.mu.Lock()
	newID := int(m.streamIDSeq.Add(1))
	holder := &streamHolder{
		id:     newID,
		conn:   conn,
		client: client,
	}
	m.addStreamInternal(holder)
	activeCount := len(m.streams)
	cb := m.onCountChange

	// Apply all stored permissions to the newly added stream
	perms := make([]net.IP, 0, len(m.permittedIPs))
	for _, p := range m.permittedIPs {
		perms = append(perms, p)
	}
	m.mu.Unlock()

	for _, p := range perms {
		if client != nil {
			go client.CreatePermission(p)
		}
	}

	log.Printf("[Stream Pool] Added stream %d to active pool. Total active: %d/%d", newID, activeCount, m.targetCount)
	if cb != nil {
		cb(activeCount, m.targetCount)
	}
}


// removeStream removes a failed/dead stream from the active pool.
func (m *MultiStreamPacketConn) removeStream(holder *streamHolder, reason error) {
	m.mu.Lock()
	if m.closed.Load() {
		m.mu.Unlock()
		return
	}

	var remaining []*streamHolder
	found := false
	for _, s := range m.streams {
		if s.id == holder.id {
			found = true
			continue
		}
		remaining = append(remaining, s)
	}
	if found {
		m.streams = remaining
	}
	activeCount := len(m.streams)
	cb := m.onCountChange
	m.mu.Unlock()

	if found {
		if holder.conn != nil {
			_ = holder.conn.Close()
		}
		if holder.client != nil {
			_ = holder.client.Disconnect()
		}
		log.Printf("[Stream Pool] Stream %d disconnected (%v). Active remaining: %d/%d", holder.id, reason, activeCount, m.targetCount)
		if cb != nil {
			cb(activeCount, m.targetCount)
		}

		// Trigger maintainer wakeup to immediately replenish missing streams
		select {
		case m.wakeChan <- struct{}{}:
		default:
		}
	}
}

// ActiveCount returns current number of alive streams.
func (m *MultiStreamPacketConn) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.streams)
}

// EnsurePermission asynchronously grants TURN permission for a peer IP across all active streams.
func (m *MultiStreamPacketConn) EnsurePermission(ip net.IP) {
	if ip == nil {
		return
	}
	m.mu.Lock()
	if m.permittedIPs == nil {
		m.permittedIPs = make(map[string]net.IP)
	}
	ipStr := ip.String()
	if _, exists := m.permittedIPs[ipStr]; exists {
		m.mu.Unlock()
		return
	}
	m.permittedIPs[ipStr] = ip
	streams := append([]*streamHolder{}, m.streams...)
	m.mu.Unlock()

	for _, holder := range streams {
		if holder.client != nil {
			go holder.client.CreatePermission(ip)
		}
	}
	log.Printf("[Stream Pool] Ensured TURN permission for peer IP %s on %d streams", ip, len(streams))
}

// EnsurePermissions asynchronously grants TURN permissions for multiple peer IPs across all streams.
func (m *MultiStreamPacketConn) EnsurePermissions(ips []net.IP) {
	for _, ip := range ips {
		m.EnsurePermission(ip)
	}
}

// AllRelayAddrs returns all active TURN relay addresses across streams in the pool.
func (m *MultiStreamPacketConn) AllRelayAddrs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var addrs []string
	for _, s := range m.streams {
		if s.conn != nil && s.conn.LocalAddr() != nil {
			addrs = append(addrs, s.conn.LocalAddr().String())
		}
	}
	return addrs
}

func (m *MultiStreamPacketConn) readWorker(holder *streamHolder) {
	buf := make([]byte, 4096)
	for !m.closed.Load() {
		n, addr, err := holder.conn.ReadFrom(buf)
		if err != nil {
			if m.closed.Load() {
				return
			}
			m.removeStream(holder, err)
			return
		}

		if n == 0 {
			continue
		}

		b := make([]byte, n)
		copy(b, buf[:n])

		select {
		case m.readChan <- packetResult{data: b, addr: addr}:
		case <-m.ctx.Done():
			return
		}
	}
}

// maintainerLoop continuously monitors active streams and automatically reconnects dropped streams.
func (m *MultiStreamPacketConn) maintainerLoop() {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.wakeChan:
			m.replenishStreams()
		case <-ticker.C:
			m.replenishStreams()
		}
	}
}

func (m *MultiStreamPacketConn) replenishStreams() {
	if m.closed.Load() {
		return
	}

	m.mu.RLock()
	currentCount := len(m.streams)
	target := m.targetCount
	creds := m.creds
	obfKey := m.obfKey
	m.mu.RUnlock()

	if currentCount >= target {
		return
	}

	missing := target - currentCount
	log.Printf("[Stream Pool] Replenishing missing streams: currently %d/%d (allocating %d new)...", currentCount, target, missing)

	for i := 0; i < missing; i++ {
		go func(idx int) {
			// Random jitter to avoid concurrent STUN bursts
			time.Sleep(time.Duration(100+rand.Intn(300)) * time.Millisecond)

			if m.closed.Load() {
				return
			}

			// 1. If credentials expired or near expiration, refresh them
			activeCreds := creds
			if activeCreds == nil || time.Now().After(activeCreds.ExpiresAt.Add(-2*time.Minute)) {
				refreshed, err := FetchVKTurnCredentials(m.ctx, activeCreds.Link)
				if err == nil && refreshed != nil {
					m.mu.Lock()
					m.creds = refreshed
					activeCreds = refreshed
					m.mu.Unlock()
					log.Printf("[Stream Pool] TURN credentials refreshed successfully")
				}
			}

			serverList := activeCreds.ServerAddrs
			if len(serverList) == 0 {
				serverList = []string{activeCreds.ServerAddr}
			}
			streamCreds := *activeCreds
			streamCreds.ServerAddr = serverList[(currentCount+idx)%len(serverList)]

			client := NewClient()
			conn, err := client.Connect(m.ctx, &streamCreds, obfKey)
			if err != nil {
				log.Printf("[Stream Pool] Failed to replenish stream: %v", err)
				return
			}

			m.AddStream(client, conn)
		}(i)
	}
}

func (m *MultiStreamPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if m.closed.Load() {
		return 0, nil, net.ErrClosed
	}

	res, ok := <-m.readChan
	if !ok || res.err != nil {
		if res.err != nil {
			return 0, res.addr, res.err
		}
		return 0, nil, net.ErrClosed
	}

	copy(p, res.data)
	return len(res.data), res.addr, nil
}

// InjectPacket delivers an incoming packet directly into the read channel from signaling/external transport.
func (m *MultiStreamPacketConn) InjectPacket(data []byte, fromAddr net.Addr) {
	if m.closed.Load() {
		return
	}
	b := make([]byte, len(data))
	copy(b, data)
	select {
	case m.readChan <- packetResult{data: b, addr: fromAddr}:
	default:
	}
}

// SetSignalingSender sets a callback to relay frames over the WebSocket channel.
func (m *MultiStreamPacketConn) SetSignalingSender(sender func(data []byte, targetAddr string)) {
	m.mu.Lock()
	m.sigSender = sender
	m.mu.Unlock()
}

func (m *MultiStreamPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	m.mu.RLock()
	connsCount := len(m.streams)
	sender := m.sigSender
	if connsCount == 0 || m.closed.Load() {
		m.mu.RUnlock()
		if sender != nil && addr != nil {
			sender(p, addr.String())
			return len(p), nil
		}
		return 0, net.ErrClosed
	}

	// For critical discovery/heartbeat frames (0x01), broadcast across all active TURN streams to punch NAT
	if len(p) > 0 && p[0] == 0x01 && connsCount > 1 {
		streamsCopy := append([]*streamHolder{}, m.streams...)
		m.mu.RUnlock()

		var firstErr error
		var sentBytes int
		for _, holder := range streamsCopy {
			n, err := holder.conn.WriteTo(p, addr)
			if err == nil && n > 0 {
				sentBytes = n
			} else if firstErr == nil {
				firstErr = err
			}
		}
		if sender != nil && addr != nil {
			sender(p, addr.String())
		}
		if sentBytes > 0 {
			return sentBytes, nil
		}
		return 0, firstErr
	}

	candidates := m.streams
	var holder *streamHolder
	if addr != nil {
		host, _, _ := net.SplitHostPort(addr.String())
		var sameServerStreams []*streamHolder
		for _, s := range candidates {
			if s.client != nil && s.client.GetServerIP() == host {
				sameServerStreams = append(sameServerStreams, s)
			}
		}

		h := fnv.New32a()
		h.Write([]byte(addr.String()))
		if len(sameServerStreams) > 0 {
			idx := int(h.Sum32() % uint32(len(sameServerStreams)))
			holder = sameServerStreams[idx]
		} else {
			idx := int(h.Sum32() % uint32(len(candidates)))
			holder = candidates[idx]
		}
	} else {
		idx := int(m.roundRobin.Add(1) % uint64(len(candidates)))
		holder = candidates[idx]
	}
	m.mu.RUnlock()

	n, err := holder.conn.WriteTo(p, addr)
	// If TURN write fails, smoothly mirror via WebSocket signaling!
	if (err != nil || n == 0) && sender != nil && addr != nil {
		sender(p, addr.String())
		return len(p), nil
	}
	return n, err
}

func (m *MultiStreamPacketConn) Close() error {
	if m.closed.Swap(true) {
		return nil
	}

	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for _, s := range m.streams {
		if s.conn != nil {
			if err := s.conn.Close(); err != nil {
				lastErr = err
			}
		}
		if s.client != nil {
			if err := s.client.Disconnect(); err != nil {
				lastErr = err
			}
		}
	}
	m.streams = nil

	return lastErr
}

func (m *MultiStreamPacketConn) LocalAddr() net.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.streams) > 0 {
		return m.streams[0].conn.LocalAddr()
	}
	return &net.UDPAddr{}
}

func (m *MultiStreamPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *MultiStreamPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MultiStreamPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// AllocateMultiStreamClient creates N parallel TURN allocations across available TURN server IPs with rtpopus3 obfuscation.
func AllocateMultiStreamClient(ctx context.Context, creds *Credentials, obfKey string, streamsCount int) (*MultiStreamPacketConn, error) {
	if streamsCount <= 0 {
		streamsCount = 3
	}
	if streamsCount > 20 {
		streamsCount = 20
	}

	serverList := creds.ServerAddrs
	if len(serverList) == 0 {
		serverList = []string{creds.ServerAddr}
	}

	log.Printf("[TURN MultiStream] Initializing %d parallel TURN streams across %d servers (%v) with rtpopus3...", streamsCount, len(serverList), serverList)

	holders := make([]*streamHolder, 0, streamsCount)
	var mu sync.Mutex
	var wg sync.WaitGroup
	errChan := make(chan error, streamsCount)

	for i := 0; i < streamsCount; i++ {
		wg.Add(1)
		go func(streamID int) {
			defer wg.Done()

			// Initial jitter
			time.Sleep(time.Duration(streamID*70) * time.Millisecond)

			streamCreds := *creds
			streamCreds.ServerAddr = serverList[streamID%len(serverList)]

			const maxAttempts = 3
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				client := NewClient()
				conn, err := client.Connect(ctx, &streamCreds, obfKey)
				if err == nil {
					mu.Lock()
					holders = append(holders, &streamHolder{
						id:     streamID + 1,
						conn:   conn,
						client: client,
					})
					mu.Unlock()
					log.Printf("[TURN MultiStream] Stream %d/%d (server: %s) connected successfully (attempt %d)", streamID+1, streamsCount, streamCreds.ServerAddr, attempt)
					return
				}

				log.Printf("[TURN MultiStream] Stream %d (server: %s) attempt %d/%d failed: %v", streamID+1, streamCreds.ServerAddr, attempt, maxAttempts, err)
				if attempt < maxAttempts {
					time.Sleep(time.Duration(200*attempt) * time.Millisecond)
				} else {
					errChan <- err
				}
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	if len(holders) == 0 {
		var firstErr error
		for e := range errChan {
			if firstErr == nil {
				firstErr = e
			}
		}
		// Clear credentials cache on allocation failure so next attempt gets fresh token
		InvalidateCredentialsCache(creds.Link)
		return nil, fmt.Errorf("failed to allocate any TURN streams: %w", firstErr)
	}

	log.Printf("[TURN MultiStream] Successfully established %d/%d parallel streams initially. Starting automatic pool maintainer...", len(holders), streamsCount)

	bondedConn := NewMultiStreamPacketConn(ctx, holders, creds, obfKey, streamsCount)
	return bondedConn, nil
}
