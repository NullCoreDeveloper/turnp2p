package turn

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// MultiStreamPacketConn bonds multiple parallel TURN relay connections into a single high-throughput PacketConn.
type MultiStreamPacketConn struct {
	conns       []net.PacketConn
	roundRobin  atomic.Uint64
	readChan    chan packetResult
	closed      atomic.Bool
	cancel      context.CancelFunc
	mu          sync.RWMutex
}

type packetResult struct {
	data []byte
	addr net.Addr
	err  error
}

// NewMultiStreamPacketConn creates a bonded packet connection over multiple TURN stream connections.
func NewMultiStreamPacketConn(conns []net.PacketConn) *MultiStreamPacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	mpc := &MultiStreamPacketConn{
		conns:    conns,
		readChan: make(chan packetResult, 512),
		cancel:   cancel,
	}

	for i, conn := range conns {
		go mpc.readWorker(ctx, i, conn)
	}

	return mpc
}

func (m *MultiStreamPacketConn) readWorker(ctx context.Context, streamIndex int, conn net.PacketConn) {
	buf := make([]byte, 4096)
	for !m.closed.Load() {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if m.closed.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}

		b := make([]byte, n)
		copy(b, buf[:n])

		select {
		case m.readChan <- packetResult{data: b, addr: addr}:
		case <-ctx.Done():
			return
		}
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

func (m *MultiStreamPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	m.mu.RLock()
	connsCount := len(m.conns)
	if connsCount == 0 || m.closed.Load() {
		m.mu.RUnlock()
		return 0, net.ErrClosed
	}

	// Round-robin striping across all allocated TURN streams
	idx := int(m.roundRobin.Add(1) % uint64(connsCount))
	conn := m.conns[idx]
	m.mu.RUnlock()

	return conn.WriteTo(p, addr)
}

func (m *MultiStreamPacketConn) Close() error {
	if m.closed.Swap(true) {
		return nil
	}

	m.cancel()

	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for _, c := range m.conns {
		if err := c.Close(); err != nil {
			lastErr = err
		}
	}
	m.conns = nil

	return lastErr
}

func (m *MultiStreamPacketConn) LocalAddr() net.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.conns) > 0 {
		return m.conns[0].LocalAddr()
	}
	return &net.UDPAddr{}
}

func (m *MultiStreamPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *MultiStreamPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MultiStreamPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// AllocateMultiStreamClient creates N parallel TURN allocations with rtpopus3 obfuscation.
func AllocateMultiStreamClient(ctx context.Context, creds *Credentials, obfKey string, streamsCount int) (net.PacketConn, []*PionClient, error) {
	if streamsCount <= 0 {
		streamsCount = 10
	}
	if streamsCount > 30 {
		streamsCount = 30
	}

	log.Printf("[TURN MultiStream] Allocating %d parallel TURN streams with rtpopus3...", streamsCount)

	clients := make([]*PionClient, 0, streamsCount)
	obfConns := make([]net.PacketConn, 0, streamsCount)

	var mu sync.Mutex
	var wg sync.WaitGroup

	errChan := make(chan error, streamsCount)

	for i := 0; i < streamsCount; i++ {
		wg.Add(1)
		go func(streamID int) {
			defer wg.Done()

			// Slight jitter to prevent VK rate limit bursts
			time.Sleep(time.Duration(streamID*80) * time.Millisecond)

			client := NewClient()
			conn, err := client.Connect(ctx, creds, obfKey)
			if err != nil {
				log.Printf("[TURN MultiStream] Stream %d failed: %v", streamID+1, err)
				errChan <- err
				return
			}

			mu.Lock()
			clients = append(clients, client)
			obfConns = append(obfConns, conn)
			mu.Unlock()

			log.Printf("[TURN MultiStream] Stream %d/%d connected successfully", streamID+1, streamsCount)
		}(i)
	}

	wg.Wait()
	close(errChan)

	if len(obfConns) == 0 {
		var firstErr error
		for e := range errChan {
			if firstErr == nil {
				firstErr = e
			}
		}
		return nil, nil, fmt.Errorf("failed to allocate any TURN streams: %w", firstErr)
	}

	log.Printf("[TURN MultiStream] Successfully established %d/%d parallel streams", len(obfConns), streamsCount)

	bondedConn := NewMultiStreamPacketConn(obfConns)
	return bondedConn, clients, nil
}
