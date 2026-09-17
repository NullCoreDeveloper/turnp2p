package turn

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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
	Data   string `json:"data"`
	Relay  string `json:"relay"`
	Target string `json:"target,omitempty"`
}

// SignalingClient manages MQTT connection for peer exchange.
type SignalingClient struct {
	roomHash   string
	obfKey     string
	aesGCM     cipher.AEAD
	client     mqtt.Client
	mu         sync.Mutex
	onPeerAddr func(relayAddr string)
	onFrame    func(data []byte, fromRelay string)
	localInfo  SignalingPeerInfo
	ctx        context.Context
	cancel     context.CancelFunc
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

	opts := mqtt.NewClientOptions().AddBroker("tcp://broker.emqx.io:1883")
	opts.SetClientID(fmt.Sprintf("turnp2p-%s-%d", s.roomHash[:8], time.Now().UnixNano()))
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(5 * time.Second)

	opts.OnConnect = func(c mqtt.Client) {
		log.Printf("[Signaling] Connected to MQTT broker (broker.emqx.io)")
		topic := fmt.Sprintf("turnp2p/room/%s", s.roomHash)
		c.Subscribe(topic, 1, func(c mqtt.Client, m mqtt.Message) {
			s.handleMessage(m.Payload())
		})
		s.broadcastAnnounce()
	}

	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Printf("[Signaling] MQTT connect error: %v", token.Error())
	}
	s.mu.Lock()
	s.client = client
	s.mu.Unlock()

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
	ticker := time.NewTicker(3 * time.Second)
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
	client := s.client
	info := s.localInfo
	s.mu.Unlock()

	if client == nil || !client.IsConnected() || info.RelayAddr == "" {
		return
	}

	info.Timestamp = time.Now().UnixMilli()
	payload, _ := json.Marshal(info)

	msg := mqttMsg{
		Type:  "turnp2p_announce",
		Room:  s.roomHash,
		Data:  string(payload),
		Relay: info.RelayAddr,
	}
	raw, _ := json.Marshal(msg)
	enc, err := s.encrypt(raw)
	if err != nil {
		return
	}

	topic := fmt.Sprintf("turnp2p/room/%s", s.roomHash)
	client.Publish(topic, 0, false, enc)
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

	if m.Room != s.roomHash || m.Relay == s.localInfo.RelayAddr || m.Relay == "" {
		return
	}

	switch m.Type {
	case "turnp2p_announce":
		// Immediate mutual announce reply to eliminate discovery latency
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
