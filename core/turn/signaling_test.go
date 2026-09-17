package turn

import (
	"bytes"
	"testing"
)

func TestSignalingEncryption(t *testing.T) {
	link := "https://vk.com/call/join/test12345"
	key := "my-secret-obf-key"

	c1 := NewSignalingClient("wss://fake", link, key)
	c2 := NewSignalingClient("wss://fake", link, key)
	cWrong := NewSignalingClient("wss://fake", link, "wrong-key")

	plaintext := []byte("hello secret peer metadata")

	enc, err := c1.encrypt(plaintext)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if bytes.Equal(enc, plaintext) {
		t.Fatalf("expected ciphertext to differ from plaintext")
	}

	dec, err := c2.decrypt(enc)
	if err != nil {
		t.Fatalf("decrypt with correct key failed: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("decrypted %s != plaintext %s", string(dec), string(plaintext))
	}

	_, err = cWrong.decrypt(enc)
	if err == nil {
		t.Fatalf("expected decrypt with wrong key to fail")
	}
}
