package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"turnp2p/core/p2p"

	"github.com/google/uuid"
)

var (
	ErrRuleAlreadyExists = errors.New("a forward rule for this local port already exists")
	ErrRuleNotFound      = errors.New("forwarding rule not found")
)

// ForwardingRule defines a local port mapping to a remote virtual IP and port in the mesh.
type ForwardingRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Protocol   string `json:"protocol"` // "TCP" or "UDP"
	LocalPort  int    `json:"localPort"`
	RemoteIP   string `json:"remoteIp"`
	RemotePort int    `json:"remotePort"`
	Enabled    bool   `json:"enabled"`
}

// RuleListener tracks the active OS listener for a rule.
type RuleListener struct {
	rule     ForwardingRule
	listener net.Listener
	closed   atomic.Bool
	cancel   context.CancelFunc
}

// Manager manages local port forwarding rules and routes them through the P2P MeshNode.
type Manager struct {
	node      *p2p.MeshNode
	rules     map[string]*RuleListener
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewManager creates a new Port Forwarding Manager.
func NewManager(node *p2p.MeshNode) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		node:   node,
		rules:  make(map[string]*RuleListener),
		ctx:    ctx,
		cancel: cancel,
	}
}

// SetMeshNode updates the active MeshNode reference.
func (m *Manager) SetMeshNode(node *p2p.MeshNode) {
	m.mu.Lock()
	m.node = node
	m.mu.Unlock()
}

// AddRule registers and immediately starts a port forwarding listener.
func (m *Manager) AddRule(rule ForwardingRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}
	if rule.Protocol == "" {
		rule.Protocol = "TCP"
	}

	// Check if local port is already taken by another rule
	for _, r := range m.rules {
		if r.rule.LocalPort == rule.LocalPort {
			return fmt.Errorf("%w: port %d is already in use by %s", ErrRuleAlreadyExists, rule.LocalPort, r.rule.Name)
		}
	}

	listenAddr := fmt.Sprintf("127.0.0.1:%d", rule.LocalPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind local port %d: %w", rule.LocalPort, err)
	}

	ruleCtx, ruleCancel := context.WithCancel(m.ctx)
	rl := &RuleListener{
		rule:     rule,
		listener: listener,
		cancel:   ruleCancel,
	}

	m.rules[rule.ID] = rl
	rule.Enabled = true

	go m.handleForwarding(ruleCtx, rl)

	log.Printf("[Proxy Manager] Port forward active: %s -> %s:%d (%s)", listenAddr, rule.RemoteIP, rule.RemotePort, rule.Name)
	return nil
}

// RemoveRule stops the listener and removes the rule.
func (m *Manager) RemoveRule(id string) error {
	m.mu.Lock()
	rl, exists := m.rules[id]
	if !exists {
		m.mu.Unlock()
		return ErrRuleNotFound
	}
	delete(m.rules, id)
	m.mu.Unlock()

	rl.cancel()
	return rl.listener.Close()
}

// ListRules returns all active forwarding rules.
func (m *Manager) ListRules() []ForwardingRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]ForwardingRule, 0, len(m.rules))
	for _, rl := range m.rules {
		res = append(res, rl.rule)
	}
	return res
}

// Stop closes all port forwarding listeners.
func (m *Manager) Stop() error {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, rl := range m.rules {
		rl.cancel()
		rl.listener.Close()
		delete(m.rules, id)
	}
	return nil
}

func (m *Manager) handleForwarding(ctx context.Context, rl *RuleListener) {
	defer rl.listener.Close()

	for {
		clientConn, err := rl.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[Proxy Manager] Accept error on port %d: %v", rl.rule.LocalPort, err)
				return
			}
		}

		go m.pipeConnection(ctx, clientConn, rl.rule)
	}
}

func (m *Manager) pipeConnection(ctx context.Context, clientConn net.Conn, rule ForwardingRule) {
	defer clientConn.Close()

	m.mu.RLock()
	node := m.node
	m.mu.RUnlock()

	if node == nil {
		log.Printf("[Proxy Manager] Cannot forward: P2P MeshNode is not active")
		return
	}

	// Dial remote peer over virtual P2P Mesh
	remoteConn, err := node.Dial(ctx, rule.RemoteIP, rule.RemotePort)
	if err != nil {
		log.Printf("[Proxy Manager] Failed to dial virtual peer %s:%d: %v", rule.RemoteIP, rule.RemotePort, err)
		return
	}
	defer remoteConn.Close()

	// Bidirectional data pipe
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(remoteConn, clientConn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, remoteConn)
		errChan <- err
	}()

	<-errChan
}
