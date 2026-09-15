package turn

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCleanVKLink(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://vk.com/call/join/abc123xyz", "abc123xyz"},
		{"https://vk.com/call/join/abc123xyz?params=1#test", "abc123xyz"},
		{"https://calls.vk.com/join/room_hash_99", "room_hash_99"},
		{"raw_join_hash", "raw_join_hash"},
	}

	for _, c := range cases {
		res := CleanVKLink(c.input)
		if res != c.expected {
			t.Errorf("CleanVKLink(%q) = %q; want %q", c.input, res, c.expected)
		}
	}
}

func TestGenerateRandomName(t *testing.T) {
	name := GenerateRandomName()
	if len(name) < 3 {
		t.Errorf("expected valid name, got %q", name)
	}
}

func TestSolvePoW(t *testing.T) {
	input := "test_pow_session_123"
	hash := solvePoW(input, 2)
	if len(hash) != 64 || hash[:2] != "00" {
		t.Fatalf("unexpected pow hash: %q", hash)
	}
}

func TestParseCaptchaBootstrapHTMLFallback(t *testing.T) {
	html := `<html><body><script>var x = 1;</script></body></html>`
	session := "session_token_fallback_123"
	bs, err := parseCaptchaBootstrapHTML(html, session)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if bs.PowInput != session {
		t.Fatalf("expected powInput = session, got %s", bs.PowInput)
	}
	if bs.Difficulty != 2 {
		t.Fatalf("expected difficulty = 2, got %d", bs.Difficulty)
	}
}

type mockPacketConn struct {
	addr net.Addr
}

func (m *mockPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	return 0, m.addr, nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return len(p), nil
}

func (m *mockPacketConn) Close() error                       { return nil }
func (m *mockPacketConn) LocalAddr() net.Addr                { return m.addr }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestMultiStreamPacketConnBonding(t *testing.T) {
	s1 := &streamHolder{id: 1, conn: &mockPacketConn{addr: &net.UDPAddr{Port: 1001}}}
	s2 := &streamHolder{id: 2, conn: &mockPacketConn{addr: &net.UDPAddr{Port: 1002}}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mpc := NewMultiStreamPacketConn(ctx, []*streamHolder{s1, s2}, nil, "dummy_key", 2)
	defer mpc.Close()

	if mpc.ActiveCount() != 2 {
		t.Fatalf("expected 2 active streams, got %d", mpc.ActiveCount())
	}

	// Test writing
	buf := []byte("HELLO_MULTI_STREAM")
	n, err := mpc.WriteTo(buf, &net.UDPAddr{Port: 9999})
	if err != nil || n != len(buf) {
		t.Fatalf("WriteTo failed: n=%d, err=%v", n, err)
	}
}


