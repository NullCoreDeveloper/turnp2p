package obf

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestRTPOpus3WrapUnwrap(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	keyHex := hex.EncodeToString(key)

	sender, err := NewRTPOpus3(keyHex)
	if err != nil {
		t.Fatalf("failed to create sender: %v", err)
	}

	receiver, err := NewRTPOpus3(keyHex)
	if err != nil {
		t.Fatalf("failed to create receiver: %v", err)
	}

	testData := []byte("Hello VK TURN P2P Mesh Network with RTP Opus 3 Obfuscation!")

	wrapped, err := sender.Wrap(testData)
	if err != nil {
		t.Fatalf("wrap failed: %v", err)
	}

	// Verify header properties
	if wrapped[0] != 0x90 {
		t.Errorf("expected RTP V2 + Ext bit, got 0x%x", wrapped[0])
	}
	if wrapped[1] != OpusPayloadType {
		t.Errorf("expected PT 111, got %d", wrapped[1])
	}

	// Receiver unwraps
	unwrapped, err := receiver.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("unwrap failed: %v", err)
	}

	if !bytes.Equal(unwrapped, testData) {
		t.Errorf("unwrapped payload mismatch! Got %q, want %q", unwrapped, testData)
	}
}

func TestRTPOpus3TamperDetection(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 32))
	sender, _ := NewRTPOpus3(key)
	receiver, _ := NewRTPOpus3(key)

	wrapped, _ := sender.Wrap([]byte("secret message"))

	// Tamper with ciphertext
	wrapped[len(wrapped)-1] ^= 0xFF

	_, err := receiver.Unwrap(wrapped)
	if err == nil {
		t.Errorf("expected decryption error on tampered packet, got nil")
	}
}
