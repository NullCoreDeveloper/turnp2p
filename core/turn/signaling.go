package turn

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

// SignalingPeerInfo represents metadata broadcasted by peers.
type SignalingPeerInfo struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	RelayAddr   string   `json:"relayAddr"`
	RelayAddrs  []string `json:"relayAddrs,omitempty"`
	VirtualIP   string   `json:"virtualIp"`
	Domain      string   `json:"domain"`
	SharedPorts []int    `json:"sharedPorts"`
	Timestamp   int64    `json:"timestamp"`
}

type mqttMsg struct {
	Type   string `json:"type"`
	Room   string `json:"room"`
	Sender string `json:"sender,omitempty"`
	Data   string `json:"data"`
	Relay  string `json:"relay"`
	Target string `json:"target,omitempty"`
}

// SignalingClient manages MQTT connection for peer exchange.
type SignalingClient struct {
	roomHash     string
	obfKey       string
	aesGCM       cipher.AEAD
	client       mqtt.Client
	mu           sync.Mutex
	onPeerAddr   func(relayAddr string)
	onFrame      func(data []byte, fromRelay string)
	localInfo    SignalingPeerInfo
	lastAnnounce time.Time
	ctx          context.Context
	cancel       context.CancelFunc
}

// NewSignalingClient creates a new MQTT signaling channel client with AES-GCM encryption.
func NewSignalingClient(wsEndpoint string, link string, obfKey string) *SignalingClient {
	clean := CleanVKLink(link)
	h := sha256.Sum256([]byte(clean))
	roomHash := hex.EncodeToString(h[:16])

	keyMaterial := obfKey
	if keyMaterial == "" {
		keyMaterial = roomHash
	}
	aesKey := sha256.Sum256([]byte(keyMaterial))
	block, err := aes.NewCipher(aesKey[:])
	var gcm cipher.AEAD
	if err == nil {
		gcm, _ = cipher.NewGCM(block)
	}

	return &SignalingClient{
		roomHash: roomHash,
		obfKey:   obfKey,
		aesGCM:   gcm,
	}
}

func (s *SignalingClient) encrypt(plaintext []byte) ([]byte, error) {
	if s.aesGCM == nil {
		return plaintext, nil
	}
	nonce := make([]byte, s.aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.aesGCM.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *SignalingClient) decrypt(ciphertext []byte) ([]byte, error) {
	if s.aesGCM == nil {
		return ciphertext, nil
	}
	nonceSize := s.aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return s.aesGCM.Open(nil, nonce, ct, nil)
}

// Start begins listening to the signaling channel and broadcasting local relay address.
func (s *SignalingClient) Start(ctx context.Context, localInfo SignalingPeerInfo, onPeerAddr func(relayAddr string), onFrame func(data []byte, fromRelay string)) {
	s.mu.Lock()
	s.localInfo = localInfo
	s.onPeerAddr = onPeerAddr
	s.onFrame = onFrame
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	log.Printf("[Signaling] Initializing signaling channel for room %s...", s.roomHash[:8])

	opts := mqtt.NewClientOptions().
		AddBroker("tcp://broker.emqx.io:1883").
		AddBroker("wss://broker.emqx.io:8084/mqtt")
	opts.SetTLSConfig(&tls.Config{InsecureSkipVerify: true})
	opts.SetClientID(fmt.Sprintf("turnp2p-%s-%d", s.roomHash[:8], time.Now().UnixNano()))
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(3 * time.Second)
	opts.SetConnectTimeout(5 * time.Second)

	opts.OnConnect = func(c mqtt.Client) {
		log.Printf("[Signaling] Connected to signaling broker (broker.emqx.io) for room %s", s.roomHash[:8])
		topic := fmt.Sprintf("turnp2p/room/%s", s.roomHash)
		if tok := c.Subscribe(topic, 0, func(c mqtt.Client, m mqtt.Message) {
			s.handleMessage(m.Payload())
		}); tok.Wait() && tok.Error() != nil {
			log.Printf("[Signaling] Subscribe error on %s: %v", topic, tok.Error())
		}
		s.broadcastAnnounce()
	}

	opts.OnConnectionLost = func(c mqtt.Client, err error) {
		log.Printf("[Signaling] Signaling connection lost: %v", err)
	}

	client := mqtt.NewClient(opts)
	s.mu.Lock()
	s.client = client
	s.mu.Unlock()

	go func() {
		token := client.Connect()
		if !token.WaitTimeout(6 * time.Second) {
			log.Printf("[Signaling] Initial connect timed out, retrying in background...")
		} else if token.Error() != nil {
			log.Printf("[Signaling] Initial connect error: %v (auto-reconnecting in background...)", token.Error())
		}
	}()

	go s.runLoop()
}

// Stop closes the signaling connection.
func (s *SignalingClient) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.client != nil {
		s.client.Disconnect(250)
	}
	s.mu.Unlock()
}

func (s *SignalingClient) runLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.broadcastAnnounce()
		}
	}
}

func (s *SignalingClient) broadcastAnnounce() {
	s.mu.Lock()
	if time.Since(s.lastAnnounce) < 2*time.Second {
		s.mu.Unlock()
		return
	}
	s.lastAnnounce = time.Now()
	client := s.client
	info := s.localInfo
	s.mu.Unlock()

	if client == nil || !client.IsConnected() || info.RelayAddr == "" {
		return
	}

	info.Timestamp = time.Now().UnixMilli()
	payload, _ := json.Marshal(info)

	msg := mqttMsg{
		Type:   "turnp2p_announce",
		Room:   s.roomHash,
		Sender: info.ID,
		Data:   string(payload),
		Relay:  info.RelayAddr,
	}
	raw, _ := json.Marshal(msg)
	enc, err := s.encrypt(raw)
	if err != nil {
		return
	}

	topic := fmt.Sprintf("turnp2p/room/%s", s.roomHash)
	client.Publish(topic, 0, false, enc)
	log.Printf("[Signaling] >>> Broadcast announce for room %s (relays: %d)", s.roomHash[:8], len(info.RelayAddrs))
}

func (s *SignalingClient) SendFrame(data []byte, targetAddr string) {
	s.mu.Lock()
	client := s.client
	info := s.localInfo
	s.mu.Unlock()

	if client == nil || !client.IsConnected() {
		return
	}

	msg := mqttMsg{
		Type:   "turnp2p_frame",
		Room:   s.roomHash,
		Sender: info.ID,
		Relay:  info.RelayAddr,
		Target: targetAddr,
		Data:   hex.EncodeToString(data),
	}
	raw, _ := json.Marshal(msg)
	enc, err := s.encrypt(raw)
	if err != nil {
		return
	}

	topic := fmt.Sprintf("turnp2p/room/%s", s.roomHash)
	client.Publish(topic, 0, false, enc)
}

func (s *SignalingClient) handleMessage(payload []byte) {
	raw, err := s.decrypt(payload)
	if err != nil {
		// Wrong encryption key or corrupt payload, ignore
		return
	}

	var m mqttMsg
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}

	s.mu.Lock()
	localID := s.localInfo.ID
	localRelay := s.localInfo.RelayAddr
	localRelays := s.localInfo.RelayAddrs
	s.mu.Unlock()

	if m.Room != s.roomHash || (m.Sender != "" && m.Sender == localID) || m.Relay == localRelay || m.Relay == "" {
		return
	}
	for _, rAddr := range localRelays {
		if rAddr != "" && m.Relay == rAddr {
			return
		}
	}

	switch m.Type {
	case "turnp2p_announce":
		log.Printf("[Signaling] <<< Received announce in room %s from sender %s (relay: %s)", m.Room[:8], m.Sender, m.Relay)
		// Immediate mutual announce reply (rate-limited inside broadcastAnnounce)
		go s.broadcastAnnounce()

		s.mu.Lock()
		cb := s.onPeerAddr
		s.mu.Unlock()
		if cb != nil {
			go cb(m.Relay)
		}

		// Also discover any additional parallel stream relays reported in payload
		if m.Data != "" {
			var pInfo SignalingPeerInfo
			if err := json.Unmarshal([]byte(m.Data), &pInfo); err == nil && len(pInfo.RelayAddrs) > 0 {
				for _, rAddr := range pInfo.RelayAddrs {
					if rAddr != "" && rAddr != m.Relay && cb != nil {
						go cb(rAddr)
					}
				}
			}
		}
	case "turnp2p_frame":
		if m.Target != "" && m.Target != s.localInfo.RelayAddr {
			return // Not for us
		}
		rawFrame, err := hex.DecodeString(m.Data)
		if err == nil {
			s.mu.Lock()
			fCb := s.onFrame
			s.mu.Unlock()
			if fCb != nil {
				go fCb(rawFrame, m.Relay)
			}
		}
	}
}
