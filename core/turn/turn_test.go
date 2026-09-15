package turn

import (
	"testing"
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
