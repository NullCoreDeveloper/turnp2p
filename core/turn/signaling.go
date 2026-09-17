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

type brokerCluster struct {
	name    string
	brokers []string
}

// SignalingClient manages multi-broker MQTT connections with redundancy and encryption.
type SignalingClient struct {
	roomHash     string
	obfKey       string
	aesGCM       cipher.AEAD
	clientsMu    sync.RWMutex
	clients      map[string]mqtt.Client
	mu           sync.Mutex
	onPeerAddr   func(relayAddr string)
	onFrame      func(data []byte, fromRelay string)
	localInfo    SignalingPeerInfo
	lastAnnounce time.Time
	seenSenders  sync.Map
	seenMsgs     sync.Map
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
		clients:  make(map[string]mqtt.Client),
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

// Start begins listening to redundant signaling clusters and broadcasting local relay address.
func (s *SignalingClient) Start(ctx context.Context, localInfo SignalingPeerInfo, onPeerAddr func(relayAddr string), onFrame func(data []byte, fromRelay string)) {
	s.mu.Lock()
	s.localInfo = localInfo
	s.onPeerAddr = onPeerAddr
	s.onFrame = onFrame
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	log.Printf("[Signaling] Initializing redundant signaling channels for room %s...", s.roomHash[:8])

	clusters := []brokerCluster{
		{
			name: "EMQX",
			brokers: []string{
				"tcp://broker.emqx.io:1883",
				"ssl://broker.emqx.io:8883",
				"wss://broker.emqx.io:8084/mqtt",
			},
		},
		{
			name: "Mosquitto",
			brokers: []string{
				"ssl://test.mosquitto.org:8883",
				"wss://test.mosquitto.org:8081/mqtt",
				"tcp://test.mosquitto.org:1883",
			},
		},
	}

	for _, c := range clusters {
		go s.runBrokerCluster(c)
	}

	go s.runLoop()
}

func (s *SignalingClient) runBrokerCluster(cluster brokerCluster) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true}
	topic := fmt.Sprintf("turnp2p/room/%s", s.roomHash)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		opts := mqtt.NewClientOptions()
		for _, b := range cluster.brokers {
			opts.AddBroker(b)
		}
		opts.SetTLSConfig(tlsConfig)
		opts.SetClientID(fmt.Sprintf("turnp2p-%s-%s-%d", cluster.name, s.roomHash[:8], time.Now().UnixNano()))
		opts.SetConnectTimeout(6 * time.Second)
		opts.SetAutoReconnect(true)
		opts.SetKeepAlive(20 * time.Second)

		opts.OnConnect = func(c mqtt.Client) {
			log.Printf("[Signaling] Connected to %s broker for room %s", cluster.name, s.roomHash[:8])
			if tok := c.Subscribe(topic, 0, func(cl mqtt.Client, m mqtt.Message) {
				s.handleMessage(m.Payload())
			}); tok.Wait() && tok.Error() != nil {
				log.Printf("[Signaling] Subscribe error on %s (%s): %v", cluster.name, topic, tok.Error())
			} else {
				log.Printf("[Signaling] Subscribed to %s for room %s", cluster.name, s.roomHash[:8])
			}
			s.broadcastAnnounce(true)
		}

		opts.OnConnectionLost = func(c mqtt.Client, err error) {
			log.Printf("[Signaling] Connection to %s lost: %v", cluster.name, err)
		}

		client := mqtt.NewClient(opts)
		tok := client.Connect()
		if tok.WaitTimeout(7*time.Second) && tok.Error() == nil && client.IsConnected() && client.IsConnectionOpen() {
			s.clientsMu.Lock()
			s.clients[cluster.name] = client
			s.clientsMu.Unlock()

			// Watchdog: monitor liveness
			for {
				select {
				case <-s.ctx.Done():
					client.Disconnect(100)
					return
				case <-time.After(2 * time.Second):
				}
				if !client.IsConnected() || !client.IsConnectionOpen() {
					log.Printf("[Signaling] Watchdog: %s connection is dead, reconnecting...", cluster.name)
					client.Disconnect(100)
					break
				}
			}
		} else {
			errStr := "timeout"
			if tok.Error() != nil {
				errStr = tok.Error().Error()
			}
			log.Printf("[Signaling] Connect to %s failed (%s), retrying in 3s...", cluster.name, errStr)
		}

		s.clientsMu.Lock()
		delete(s.clients, cluster.name)
		s.clientsMu.Unlock()

		select {
		case <-s.ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

// Stop closes all signaling connections.
func (s *SignalingClient) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()

	s.clientsMu.Lock()
	for _, client := range s.clients {
		if client != nil {
			client.Disconnect(250)
		}
	}
	s.clients = make(map[string]mqtt.Client)
	s.clientsMu.Unlock()
}

func (s *SignalingClient) runLoop() {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.broadcastAnnounce(false)
		}
	}
}

func (s *SignalingClient) broadcastAnnounce(force bool) {
	s.mu.Lock()
	now := time.Now()
	if !force && now.Sub(s.lastAnnounce) < 2*time.Second {
		s.mu.Unlock()
		return
	}
	s.lastAnnounce = now
	info := s.localInfo
	s.mu.Unlock()

	if info.RelayAddr == "" {
		return
	}

	info.Timestamp = now.UnixMilli()
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
	sent := s.publishAll(topic, enc)
	if sent > 0 {
		log.Printf("[Signaling] >>> Broadcast announce for room %s (relays: %d, sent_to: %d brokers, force: %v)", s.roomHash[:8], len(info.RelayAddrs), sent, force)
	}
}

func (s *SignalingClient) publishAll(topic string, payload []byte) int {
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	sent := 0
	for _, client := range s.clients {
		if client != nil && client.IsConnected() && client.IsConnectionOpen() {
			client.Publish(topic, 0, false, payload)
			sent++
		}
	}
	return sent
}

func (s *SignalingClient) SendFrame(data []byte, targetAddr string) {
	s.mu.Lock()
	info := s.localInfo
	s.mu.Unlock()

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
	s.publishAll(topic, enc)
}

func (s *SignalingClient) handleMessage(payload []byte) {
	// Deduplicate identical packets received from multiple brokers
	h := sha256.Sum256(payload)
	now := time.Now()
	if val, ok := s.seenMsgs.Load(h); ok {
		if t, ok := val.(time.Time); ok && now.Sub(t) < 5*time.Second {
			return
		}
	}
	s.seenMsgs.Store(h, now)

	raw, err := s.decrypt(payload)
	if err != nil {
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

		// Check if we already replied to this sender recently
		shouldReply := false
		if m.Sender != "" {
			if val, ok := s.seenSenders.Load(m.Sender); !ok {
				s.seenSenders.Store(m.Sender, now)
				shouldReply = true
			} else if lastTime, ok := val.(time.Time); ok && now.Sub(lastTime) > 10*time.Second {
				s.seenSenders.Store(m.Sender, now)
				shouldReply = true
			}
		} else {
			shouldReply = true
		}

		if shouldReply {
			// Immediately reply to newcomer with force=true so they receive our relay address instantly!
			go s.broadcastAnnounce(true)
		}

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
