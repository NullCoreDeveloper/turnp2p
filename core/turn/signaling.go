package turn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// SignalingPeerInfo represents metadata broadcasted by peers over VK call WebSocket.
type SignalingPeerInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	RelayAddr   string `json:"relayAddr"`
	VirtualIP   string `json:"virtualIp"`
	Domain      string `json:"domain"`
	SharedPorts []int  `json:"sharedPorts"`
	Timestamp   int64  `json:"timestamp"`
}

// SignalingClient manages WebSocket connection to the VK Call signaling server for peer exchange.
type SignalingClient struct {
	wsEndpoint string
	roomHash   string
	obfKey     string
	conn       *websocket.Conn
	mu         sync.Mutex
	onPeerAddr func(relayAddr string)
	onFrame    func(data []byte, fromRelay string)
	localInfo  SignalingPeerInfo
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewSignalingClient creates a new VK Call signaling channel client.
func NewSignalingClient(wsEndpoint string, link string, obfKey string) *SignalingClient {
	// roomHash is derived from the VK link ONLY so all peers in the same room
	// compute the same hash regardless of their individual obfKey.
	// The obfKey is a per-session TURN encryption key and must NOT be mixed in here.
	h := sha256.Sum256([]byte(link))
	roomHash := hex.EncodeToString(h[:16])

	return &SignalingClient{
		wsEndpoint: wsEndpoint,
		roomHash:   roomHash,
		obfKey:     obfKey,
	}
}

// Start begins listening to the signaling channel and broadcasting local relay address.
func (s *SignalingClient) Start(ctx context.Context, localInfo SignalingPeerInfo, onPeerAddr func(relayAddr string), onFrame func(data []byte, fromRelay string)) {
	s.mu.Lock()
	s.localInfo = localInfo
	s.onPeerAddr = onPeerAddr
	s.onFrame = onFrame
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	go s.runLoop()
}

// Stop closes the signaling connection.
func (s *SignalingClient) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
}

func (s *SignalingClient) runLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		if s.wsEndpoint == "" {
			time.Sleep(2 * time.Second)
			continue
		}

		wsURL := s.wsEndpoint
		devID := fmt.Sprintf("turnp2p-%x", s.roomHash)
		if !strings.Contains(wsURL, "appVersion=") {
			sep := "?"
			if strings.Contains(wsURL, "?") {
				sep = "&"
			}
			wsURL = fmt.Sprintf("%s%sappVersion=1.1&client_type=SDK_JS&device_idx=0&device=%s&device_id=%s&version=2", wsURL, sep, devID, devID)
		}

		dialer := websocket.DefaultDialer
		dialer.HandshakeTimeout = 5 * time.Second
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		headers.Set("Origin", "https://vk.ru")

		conn, _, err := dialer.DialContext(s.ctx, wsURL, headers)
		if err != nil {
			log.Printf("[Signaling] WebSocket connect error: %v, retrying in 3s...", err)
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(3 * time.Second):
				continue
			}
		}

		s.mu.Lock()
		s.conn = conn
		s.mu.Unlock()

		log.Printf("[Signaling] Connected to VK Call WebSocket channel (%s)", s.localInfo.RelayAddr)

		// Broadcast loop
		broadcastTicker := time.NewTicker(2 * time.Second)
		readDone := make(chan struct{})

		// Start reader
		go func() {
			defer close(readDone)
			for {
				_, msg, err := conn.ReadMessage()
				if err != nil {
					return
				}
				s.handleMessage(msg)
			}
		}()

		// Periodic announce
		s.broadcastAnnounce()

	loop:
		for {
			select {
			case <-s.ctx.Done():
				broadcastTicker.Stop()
				_ = conn.Close()
				return
			case <-readDone:
				broadcastTicker.Stop()
				break loop
			case <-broadcastTicker.C:
				s.broadcastAnnounce()
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func (s *SignalingClient) broadcastAnnounce() {
	s.mu.Lock()
	conn := s.conn
	info := s.localInfo
	s.mu.Unlock()

	if conn == nil || info.RelayAddr == "" {
		return
	}

	info.Timestamp = time.Now().UnixMilli()
	payload, err := json.Marshal(info)
	if err != nil {
		return
	}

	// Encapsulate in custom event frame
	msgObj := map[string]interface{}{
		"type":     "turnp2p_announce",
		"room":     s.roomHash,
		"data":     string(payload),
		"relay":    info.RelayAddr,
		"sendTime": time.Now().UnixMilli(),
	}

	raw, _ := json.Marshal(msgObj)
	log.Printf("[Signaling] >>> Sending announce: relay=%s room=%s", info.RelayAddr, s.roomHash)
	if err := conn.WriteMessage(websocket.TextMessage, raw); err != nil {
		log.Printf("[Signaling] >>> Send error: %v", err)
	}
}

// SendFrame transmits a data/mesh frame to peers via the WebSocket signaling transport.
func (s *SignalingClient) SendFrame(data []byte, targetAddr string) {
	s.mu.Lock()
	conn := s.conn
	info := s.localInfo
	s.mu.Unlock()

	if conn == nil {
		return
	}

	msgObj := map[string]interface{}{
		"type":   "turnp2p_frame",
		"room":   s.roomHash,
		"relay":  info.RelayAddr,
		"target": targetAddr,
		"data":   hex.EncodeToString(data),
	}

	raw, _ := json.Marshal(msgObj)
	_ = conn.WriteMessage(websocket.TextMessage, raw)
}

func (s *SignalingClient) handleMessage(msg []byte) {
	var obj map[string]interface{}
	if err := json.Unmarshal(msg, &obj); err != nil {
		// VK may send binary/non-JSON frames — log raw
		log.Printf("[Signaling] <<< RAW (non-JSON, %d bytes): %s", len(msg), truncate(string(msg), 400))
		return
	}

	msgType, _ := obj["type"].(string)

	// Log everything the VK server sends us (helps diagnose the protocol)
	if msgType != "turnp2p_announce" && msgType != "turnp2p_frame" {
		raw, _ := json.Marshal(obj)
		log.Printf("[Signaling] <<< VK server msg type=%q: %s", msgType, truncate(string(raw), 500))
	}

	// Verify room hash
	if obj["room"] != s.roomHash {
		// Only log non-VK messages so we don't spam with VK's own protocol frames
		if msgType == "turnp2p_announce" || msgType == "turnp2p_frame" {
			log.Printf("[Signaling] Dropped msg (wrong room): expected=%s got=%v", s.roomHash, obj["room"])
		}
		return
	}

	relay, _ := obj["relay"].(string)
	if relay == s.localInfo.RelayAddr {
		return
	}

	switch msgType {
	case "turnp2p_announce":
		if relay != "" {
			log.Printf("[Signaling] <<< Discovered peer relay: %s", relay)
			s.mu.Lock()
			cb := s.onPeerAddr
			s.mu.Unlock()

			if cb != nil {
				cb(relay)
			}
		}
	case "turnp2p_frame":
		hexData, _ := obj["data"].(string)
		if hexData != "" {
			raw, err := hex.DecodeString(hexData)
			if err == nil {
				s.mu.Lock()
				fCb := s.onFrame
				s.mu.Unlock()

				if fCb != nil {
					fCb(raw, relay)
				}
			}
		}
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}
