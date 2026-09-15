package turn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
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
	localInfo  SignalingPeerInfo
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewSignalingClient creates a new VK Call signaling channel client.
func NewSignalingClient(wsEndpoint string, link string, obfKey string) *SignalingClient {
	h := sha256.Sum256([]byte(link + ":" + obfKey))
	roomHash := hex.EncodeToString(h[:16])

	return &SignalingClient{
		wsEndpoint: wsEndpoint,
		roomHash:   roomHash,
		obfKey:     obfKey,
	}
}

// Start begins listening to the signaling channel and broadcasting local relay address.
func (s *SignalingClient) Start(ctx context.Context, localInfo SignalingPeerInfo, onPeerAddr func(relayAddr string)) {
	s.mu.Lock()
	s.localInfo = localInfo
	s.onPeerAddr = onPeerAddr
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

		dialer := websocket.DefaultDialer
		dialer.HandshakeTimeout = 5 * time.Second
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
		headers.Set("Origin", "https://vk.ru")

		conn, _, err := dialer.DialContext(s.ctx, s.wsEndpoint, headers)
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
	_ = conn.WriteMessage(websocket.TextMessage, raw)
}

func (s *SignalingClient) handleMessage(msg []byte) {
	var obj map[string]interface{}
	if err := json.Unmarshal(msg, &obj); err != nil {
		return
	}

	// Check if this is a TurnP2P announce
	if obj["type"] == "turnp2p_announce" && obj["room"] == s.roomHash {
		relay, _ := obj["relay"].(string)
		if relay != "" && relay != s.localInfo.RelayAddr {
			s.mu.Lock()
			cb := s.onPeerAddr
			s.mu.Unlock()

			if cb != nil {
				cb(relay)
			}
		}
	}
}
