package hosts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostsManagerSyncAndClean(t *testing.T) {
	tempDir := t.TempDir()
	hostsFile := filepath.Join(tempDir, "test_hosts")

	initialContent := "127.0.0.1 localhost\n::1 localhost\n"
	if err := os.WriteFile(hostsFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("write initial hosts: %v", err)
	}

	mgr := NewManager(hostsFile)

	// 1. Sync entries
	entries := map[string]string{
		"server.vkturn": "10.42.0.5",
		"craft.vkturn":  "10.42.0.6",
	}

	if err := mgr.Sync(entries); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	contentBytes, err := os.ReadFile(hostsFile)
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	content := string(contentBytes)

	if !strings.Contains(content, "127.0.0.1 localhost") {
		t.Fatalf("initial content lost: %s", content)
	}
	if !strings.Contains(content, "10.42.0.5") || !strings.Contains(content, "server.vkturn") {
		t.Fatalf("server.vkturn missing in hosts: %s", content)
	}
	if !strings.Contains(content, "10.42.0.6") || !strings.Contains(content, "craft.vkturn") {
		t.Fatalf("craft.vkturn missing in hosts: %s", content)
	}

	// 2. Update with new entries
	updatedEntries := map[string]string{
		"alphanode.vkturn": "10.42.0.99",
	}
	if err := mgr.Sync(updatedEntries); err != nil {
		t.Fatalf("Sync update failed: %v", err)
	}

	contentBytes, _ = os.ReadFile(hostsFile)
	content = string(contentBytes)
	if strings.Contains(content, "server.vkturn") {
		t.Fatalf("old entry server.vkturn should have been removed: %s", content)
	}
	if !strings.Contains(content, "alphanode.vkturn") || !strings.Contains(content, "10.42.0.99") {
		t.Fatalf("new entry missing: %s", content)
	}

	// 3. Clean
	if err := mgr.Clean(); err != nil {
		t.Fatalf("Clean failed: %v", err)
	}

	contentBytes, _ = os.ReadFile(hostsFile)
	content = string(contentBytes)
	if strings.Contains(content, markerBegin) || strings.Contains(content, "newserver.vkturn") {
		t.Fatalf("TurnP2P marker still present after Clean: %s", content)
	}
	if !strings.Contains(content, "127.0.0.1 localhost") {
		t.Fatalf("initial localhost lost after Clean: %s", content)
	}
}
