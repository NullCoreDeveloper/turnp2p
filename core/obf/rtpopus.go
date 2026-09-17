package obf

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	ProfileNone     = "none"
	ProfileRTPOpus  = "rtpopus"
	ProfileRTPOpus2 = "rtpopus2"
	ProfileRTPOpus3 = "rtpopus3"

	// Opus clock rate is 48 kHz. A 20 ms frame is 960 samples.
	OpusClockRate       = 48000
	OpusFrameDuration   = 20 * time.Millisecond
	OpusSamplesPerFrame = 960

	// RTP Constants
	RTPVersion      = 2
	OpusPayloadType = 111
	RFC8285HeaderID = 0xBEDE // One-byte header extension profile
)

var (
	ErrInvalidPacket   = errors.New("invalid or malformed obfuscated packet")
	ErrDecryptFailed   = errors.New("failed to decrypt packet payload (AEAD auth failed)")
	ErrUnsupportedMode = errors.New("unsupported obfuscation profile")
)

// Obfuscator defines the interface for packet wrapping/unwrapping.
type Obfuscator interface {
	Wrap(payload []byte) ([]byte, error)
	Unwrap(packet []byte) ([]byte, error)
}

// RTPOpus3 implements the rtpopus3 obfuscation profile matching WebRTC VK voice traffic.
type RTPOpus3 struct {
	aead          cipher.AEAD
	ssrc          uint32
	seq           atomic.Uint32
	timestamp     atomic.Uint32
	packetCounter atomic.Uint64
	bufPool       sync.Pool
}

// NewRTPOpus3 initializes an RTPOpus3 obfuscator with the given 32-byte key (or 64 hex chars / passphrase).
func NewRTPOpus3(keyHexOrBytes string) (*RTPOpus3, error) {
	var key []byte
	var err error

	keyHexOrBytes = strings.TrimSpace(keyHexOrBytes)
	if len(keyHexOrBytes) == 64 {
		key, err = hex.DecodeString(keyHexOrBytes)
		if err != nil {
			key = nil
		}
	}
	if len(key) == 0 && len(keyHexOrBytes) == 32 {
		key = []byte(keyHexOrBytes)
	}
	if len(key) == 0 {
		// Deterministically derive 32-byte ChaCha20 key from any passphrase or string
		h := sha256.Sum256([]byte(keyHexOrBytes))
		key = h[:]
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create chacha20poly1305: %w", err)
	}

	n, _ := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFF))
	ssrc := uint32(n.Int64())

	o := &RTPOpus3{
		aead: aead,
		ssrc: ssrc,
		bufPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, 2048)
				return &b
			},
		},
	}

	initSeq, _ := rand.Int(rand.Reader, big.NewInt(0xFFFF))
	o.seq.Store(uint32(initSeq.Int64()))

	initTs, _ := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFF))
	o.timestamp.Store(uint32(initTs.Int64()))

	return o, nil
}

// Wrap encodes raw data into an rtpopus3 packet.
func (o *RTPOpus3) Wrap(payload []byte) ([]byte, error) {
	seq := uint16(o.seq.Add(1))
	ts := o.timestamp.Add(OpusSamplesPerFrame)
	counter := o.packetCounter.Add(1)

	// Total header size: 12 (RTP) + 4 (Ext Header) + 2 (Ext 1) + 9 (Ext 2) + 1 (Padding) = 28 bytes
	const headerSize = 28
	packet := make([]byte, headerSize+len(payload)+o.aead.Overhead())

	// 1. RTP Header
	packet[0] = 0x90 // V=2, P=0, X=1 (extension present), CC=0
	packet[1] = OpusPayloadType & 0x7F // M=0, PT=111
	binary.BigEndian.PutUint16(packet[2:4], seq)
	binary.BigEndian.PutUint32(packet[4:8], ts)
	binary.BigEndian.PutUint32(packet[8:12], o.ssrc)

	// 2. RFC 8285 Extension Header
	binary.BigEndian.PutUint16(packet[12:14], RFC8285HeaderID)
	binary.BigEndian.PutUint16(packet[14:16], 3) // 3 32-bit words follow (12 bytes)

	// Ext 1: ID 1 (Audio level), Len 0 (1 byte data)
	packet[16] = 0x10
	packet[17] = 0x7F // Audio level

	// Ext 2: ID 3 (Packet Counter), Len 7 (8 bytes data)
	packet[18] = 0x37
	binary.BigEndian.PutUint64(packet[19:27], counter)

	// Padding
	packet[27] = 0x00

	// 3. Construct 12-byte Nonce from SSRC (4b) + PacketCounter (8b)
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], o.ssrc)
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	// 4. Encrypt payload with AEAD using the 28-byte header as AAD
	aad := packet[:headerSize]
	o.aead.Seal(packet[:headerSize], nonce[:], payload, aad)

	return packet, nil
}

// Unwrap decodes and verifies an rtpopus3 packet.
func (o *RTPOpus3) Unwrap(packet []byte) ([]byte, error) {
	const headerSize = 28
	if len(packet) < headerSize+o.aead.Overhead() {
		return nil, ErrInvalidPacket
	}

	// Verify RTP Version 2 and Extension bit
	if (packet[0] >> 6) != RTPVersion || (packet[0]&0x10) == 0 {
		return nil, ErrInvalidPacket
	}

	// Verify Payload Type 111
	if (packet[1] & 0x7F) != OpusPayloadType {
		return nil, ErrInvalidPacket
	}

	// Verify Extension Profile 0xBEDE
	if binary.BigEndian.Uint16(packet[12:14]) != RFC8285HeaderID {
		return nil, ErrInvalidPacket
	}

	seq := binary.BigEndian.Uint16(packet[2:4])
	_ = seq // Ignored for nonce, but part of RTP header
	ts := binary.BigEndian.Uint32(packet[4:8])
	_ = ts
	ssrc := binary.BigEndian.Uint32(packet[8:12])

	// Read counter from Ext 2 (assuming fixed position per our Wrap logic)
	// Ext 2 starts at byte 18: [18]=0x37, [19:27] = counter
	if packet[18] != 0x37 {
		return nil, ErrInvalidPacket
	}
	counter := binary.BigEndian.Uint64(packet[19:27])

	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], ssrc)
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	aad := packet[:headerSize]
	ciphertext := packet[headerSize:]

	plaintext, err := o.aead.Open(nil, nonce[:], ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}

// ObfuscatedPacketConn wraps a net.PacketConn with automatic rtpopus3 encryption/decryption.
type ObfuscatedPacketConn struct {
	net.PacketConn
	obf Obfuscator
}

func NewObfuscatedPacketConn(conn net.PacketConn, obf Obfuscator) *ObfuscatedPacketConn {
	return &ObfuscatedPacketConn{
		PacketConn: conn,
		obf:        obf,
	}
}

func (c *ObfuscatedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}

		plain, err := c.obf.Unwrap(buf[:n])
		if err != nil {
			log.Printf("[obf] ReadFrom: received %d bytes from %s but decryption FAILED: %v", n, addr, err)
			continue
		}

		copy(p, plain)
		return len(plain), addr, nil
	}
}

func (c *ObfuscatedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	wrapped, err := c.obf.Wrap(p)
	if err != nil {
		return 0, err
	}

	_, err = c.PacketConn.WriteTo(wrapped, addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}
