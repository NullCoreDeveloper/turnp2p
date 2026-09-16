package turn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	wsEndpoint   string
	roomHash     string
	convID       string
	obfKey       string
	myUserID     string
	myInternalID int64
	participants map[int64]string // key: participantId -> participantType
	peerIDs      map[int64]int64  // key: participantId -> peerId
	seq          int64
	conn         *websocket.Conn
	writeMu      sync.Mutex
	mu           sync.Mutex
	onPeerAddr   func(relayAddr string)
	onFrame      func(data []byte, fromRelay string)
	localInfo    SignalingPeerInfo
	ctx          context.Context
	cancel       context.CancelFunc
}

func (s *SignalingClient) writeMsg(msgType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return net.ErrClosed
	}
	return conn.WriteMessage(msgType, data)
}

// NewSignalingClient creates a new VK Call signaling channel client.
func NewSignalingClient(wsEndpoint string, link string, obfKey string) *SignalingClient {
	clean := CleanVKLink(link)
	convID := clean
	myUID := ""

	if u, err := neturl.Parse(wsEndpoint); err == nil {
		myUID = u.Query().Get("userId")
		if cid := u.Query().Get("conversationId"); cid != "" {
			convID = cid
		}
	}

	h := sha256.Sum256([]byte(convID))
	roomHash := hex.EncodeToString(h[:16])

	return &SignalingClient{
		wsEndpoint:   wsEndpoint,
		roomHash:     roomHash,
		convID:       convID,
		obfKey:       obfKey,
		myUserID:     myUID,
		participants: make(map[int64]string),
		peerIDs:      make(map[int64]int64),
	}
}

func (s *SignalingClient) nextSeq() int64 {
	return atomic.AddInt64(&s.seq, 1)
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
		s.participants = make(map[int64]string)
		s.peerIDs = make(map[int64]int64)
		s.mu.Unlock()

		log.Printf("[Signaling] Connected to VK Call WebSocket channel (%s)", s.localInfo.RelayAddr)

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
	type partTarget struct {
		id     int64
		pType  string
		peerID int64
	}
	targets := make([]partTarget, 0, len(s.participants))
	for pid, pType := range s.participants {
		targets = append(targets, partTarget{id: pid, pType: pType, peerID: s.peerIDs[pid]})
	}
	s.mu.Unlock()

	if conn == nil || info.RelayAddr == "" {
		return
	}

	info.Timestamp = time.Now().UnixMilli()
	payload, err := json.Marshal(info)
	if err != nil {
		return
	}

	msgObj := map[string]interface{}{
		"type":     "turnp2p_announce",
		"room":     s.roomHash,
		"convId":   s.convID,
		"data":     string(payload),
		"relay":    info.RelayAddr,
		"sendTime": time.Now().UnixMilli(),
	}

	rawMsg, err := json.Marshal(msgObj)
	if err != nil {
		return
	}
	dataStr := string(rawMsg)

	// 1. Send targeted transmit-data to each participant via VK Call protocol
	for _, target := range targets {
		transmitCmd := map[string]interface{}{
			"command":         "transmit-data",
			"sequence":        s.nextSeq(),
			"participantId":   target.id,
			"participantType": "USER",
			"data":            dataStr,
		}
		if raw, err := json.Marshal(transmitCmd); err == nil {
			_ = s.writeMsg(websocket.TextMessage, raw)
		}

		if target.peerID > 0 {
			peerCmd := map[string]interface{}{
				"command":  "transmit-data",
				"sequence": s.nextSeq(),
				"peerId": map[string]interface{}{
					"id":   target.peerID,
					"type": "WEB_SOCKET",
				},
				"data": dataStr,
			}
			if rawP, err := json.Marshal(peerCmd); err == nil {
				_ = s.writeMsg(websocket.TextMessage, rawP)
			}
		}
	}

	// 2. Also send broadcast custom-data to the conversation room
	customCmd := map[string]interface{}{
		"command":  "custom-data",
		"sequence": s.nextSeq(),
		"data":     dataStr,
	}
	if rawC, err := json.Marshal(customCmd); err == nil {
		_ = s.writeMsg(websocket.TextMessage, rawC)
	}

	if len(targets) > 0 {
		log.Printf("[Signaling] >>> Broadcast announce to %d peers: relay=%s room=%s", len(targets), info.RelayAddr, s.roomHash)
	}
}

// SendFrame transmits a data/mesh frame to peers via the WebSocket signaling transport.
func (s *SignalingClient) SendFrame(data []byte, targetAddr string) {
	s.mu.Lock()
	conn := s.conn
	info := s.localInfo
	type partTarget struct {
		id     int64
		pType  string
		peerID int64
	}
	targets := make([]partTarget, 0, len(s.participants))
	for pid, pType := range s.participants {
		targets = append(targets, partTarget{id: pid, pType: pType, peerID: s.peerIDs[pid]})
	}
	s.mu.Unlock()

	if conn == nil {
		return
	}

	msgObj := map[string]interface{}{
		"type":   "turnp2p_frame",
		"room":   s.roomHash,
		"convId": s.convID,
		"relay":  info.RelayAddr,
		"target": targetAddr,
		"data":   hex.EncodeToString(data),
	}

	rawMsg, err := json.Marshal(msgObj)
	if err != nil {
		return
	}
	dataStr := string(rawMsg)

	for _, target := range targets {
		transmitCmd := map[string]interface{}{
			"command":         "transmit-data",
			"sequence":        s.nextSeq(),
			"participantId":   target.id,
			"participantType": "USER",
			"data":            dataStr,
		}
		if raw, err := json.Marshal(transmitCmd); err == nil {
			_ = s.writeMsg(websocket.TextMessage, raw)
		}
	}
}

func (s *SignalingClient) handleMessage(msg []byte) {
	// Handle ping/pong heartbeat from VK server
	if string(msg) == "ping" {
		_ = s.writeMsg(websocket.TextMessage, []byte("pong"))
		return
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(msg, &obj); err != nil {
		log.Printf("[Signaling] <<< RAW (%d bytes): %s", len(msg), truncate(string(msg), 400))
		return
	}

	msgType, _ := obj["type"].(string)
	notifType, _ := obj["notification"].(string)

	// Check for ServerHello or conversation updates containing participants
	if conv, ok := obj["conversation"].(map[string]interface{}); ok {
		s.updateParticipantsFromConversation(conv)
	}

	if notifType == "participant-joined" {
		if part, ok := obj["participant"].(map[string]interface{}); ok {
			pid := parseParticipantID(part["id"])
			pType, _ := part["type"].(string)
			if pType == "" {
				pType = "ANONYMOUS_USER"
			}
			isSelf := fmt.Sprintf("%d", pid) == s.myUserID || (s.myInternalID > 0 && pid == s.myInternalID)
			if pid > 0 && !isSelf {
				s.mu.Lock()
				s.participants[pid] = pType
				s.mu.Unlock()
				log.Printf("[Signaling] Peer joined call: participantId=%d (type=%s)", pid, pType)
				go s.broadcastAnnounce()
			}
		}
	} else if notifType == "registered-peer" {
		pid := parseParticipantID(obj["participantId"])
		if peerObj, ok := obj["peerId"].(map[string]interface{}); ok {
			peerID := parseParticipantID(peerObj["id"])
			if pid > 0 && peerID > 0 {
				s.mu.Lock()
				s.peerIDs[pid] = peerID
				s.mu.Unlock()
				log.Printf("[Signaling] Registered peer: participantId=%d -> peerId=%d", pid, peerID)
				go s.broadcastAnnounce()
			}
		}
	} else if notifType == "participant-left" {
		if part, ok := obj["participant"].(map[string]interface{}); ok {
			pid := parseParticipantID(part["id"])
			if pid > 0 {
				s.mu.Lock()
				delete(s.participants, pid)
				delete(s.peerIDs, pid)
				s.mu.Unlock()
				log.Printf("[Signaling] Peer left call: participantId=%d", pid)
			}
		}
	} else if notifType == "transmitted-data" || notifType == "data" || notifType == "custom-data" || notifType == "send-data" {
		// Data received from another peer via VK call signaling!
		var dataMap map[string]interface{}
		switch d := obj["data"].(type) {
		case map[string]interface{}:
			dataMap = d
		case string:
			_ = json.Unmarshal([]byte(d), &dataMap)
		}

		if dataMap != nil {
			s.handleTurnP2PData(dataMap)
			return
		}
	}

	// Also handle direct message formats or stringified data payloads
	if msgType == "turnp2p_announce" || msgType == "turnp2p_frame" {
		s.handleTurnP2PData(obj)
		return
	}

	// Check if obj itself has data field with turnp2p message
	if dMap, ok := obj["data"].(map[string]interface{}); ok {
		if dt, _ := dMap["type"].(string); strings.HasPrefix(dt, "turnp2p_") {
			s.handleTurnP2PData(dMap)
			return
		}
	} else if dStr, ok := obj["data"].(string); ok {
		var dMap map[string]interface{}
		if err := json.Unmarshal([]byte(dStr), &dMap); err == nil {
			if dt, _ := dMap["type"].(string); strings.HasPrefix(dt, "turnp2p_") {
				s.handleTurnP2PData(dMap)
				return
			}
		}
	}

	raw, _ := json.Marshal(obj)
	if notifType != "" {
		log.Printf("[Signaling] <<< VK notification=%q: %s", notifType, truncate(string(raw), 400))
	} else if msgType != "response" {
		log.Printf("[Signaling] <<< VK msg type=%q: %s", msgType, truncate(string(raw), 400))
	}
}

func (s *SignalingClient) updateParticipantsFromConversation(conv map[string]interface{}) {
	parts, ok := conv["participants"].([]interface{})
	if !ok {
		return
	}

	s.mu.Lock()
	newPeers := 0
	for _, p := range parts {
		pmap, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		pid := parseParticipantID(pmap["id"])
		if pid == 0 {
			continue
		}
		pType, _ := pmap["type"].(string)
		if pType == "" {
			pType = "ANONYMOUS_USER"
		}

		// Check if this participant is myself (match URL userId directly)
		isSelf := false
		if fmt.Sprintf("%d", pid) == s.myUserID || (s.myInternalID > 0 && pid == s.myInternalID) {
			s.myInternalID = pid
			isSelf = true
		}
		if ext, ok := pmap["externalId"].(map[string]interface{}); ok {
			extID := fmt.Sprintf("%v", ext["id"])
			if extID != "" && extID == s.myUserID {
				s.myInternalID = pid
				isSelf = true
			}
		}

		if !isSelf && pid != s.myInternalID {
			if _, exists := s.participants[pid]; !exists {
				s.participants[pid] = pType
				newPeers++
			}
		}
	}
	total := len(s.participants)
	s.mu.Unlock()

	if newPeers > 0 {
		log.Printf("[Signaling] Discovered %d other participant(s) in call room (total: %d)", newPeers, total)
		go s.broadcastAnnounce()
	}
}

func (s *SignalingClient) handleTurnP2PData(obj map[string]interface{}) {
	relay, _ := obj["relay"].(string)
	if relay == s.localInfo.RelayAddr || relay == "" {
		return
	}

	msgType, _ := obj["type"].(string)
	switch msgType {
	case "turnp2p_announce":
		log.Printf("[Signaling] <<< Discovered peer relay via call channel: %s", relay)
		s.mu.Lock()
		cb := s.onPeerAddr
		s.mu.Unlock()
		if cb != nil {
			cb(relay)
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

func parseParticipantID(val interface{}) int64 {
	switch v := val.(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	default:
		return 0
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}
