package hosts

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

const (
	markerBegin = "# BEGIN TurnP2P Mesh Hosts (Do not modify manually)"
	markerEnd   = "# END TurnP2P Mesh Hosts"
)

// Manager handles adding and removing domain-to-IP mappings in the OS hosts file.
type Manager struct {
	hostsPath string
	mu        sync.Mutex
}

// DefaultHostsPath returns the platform-specific path to the hosts file.
func DefaultHostsPath() string {
	if runtime.GOOS == "windows" {
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = "C:\\Windows"
		}
		return filepath.Join(systemRoot, "System32", "drivers", "etc", "hosts")
	}
	return "/etc/hosts"
}

// NewManager creates a hosts manager.
func NewManager(customPath string) *Manager {
	if customPath == "" {
		customPath = DefaultHostsPath()
	}
	return &Manager{
		hostsPath: customPath,
	}
}

// Sync updates the hosts file with current domain mappings.
// If entries is empty, cleans up the TurnP2P section entirely.
func (m *Manager) Sync(entries map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.hostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			data = []byte("")
		} else {
			return fmt.Errorf("read hosts file (%s): %w", m.hostsPath, err)
		}
	}

	content := string(data)
	cleaned := removeTurnP2PBlock(content)

	if len(entries) == 0 {
		return os.WriteFile(m.hostsPath, []byte(cleaned), 0644)
	}

	var sb strings.Builder
	sb.WriteString(cleaned)
	if !strings.HasSuffix(cleaned, "\n") && len(cleaned) > 0 {
		sb.WriteString("\n")
	}

	sb.WriteString(markerBegin + "\n")
	for domain, ip := range entries {
		domain = strings.TrimSpace(domain)
		ip = strings.TrimSpace(ip)
		if domain != "" && ip != "" {
			sb.WriteString(fmt.Sprintf("%-15s %s\n", ip, domain))
		}
	}
	sb.WriteString(markerEnd + "\n")

	return os.WriteFile(m.hostsPath, []byte(sb.String()), 0644)
}

// Clean removes all TurnP2P entries from the hosts file.
func (m *Manager) Clean() error {
	return m.Sync(nil)
}

func removeTurnP2PBlock(content string) string {
	beginIdx := strings.Index(content, markerBegin)
	if beginIdx == -1 {
		return content
	}

	endIdx := strings.Index(content, markerEnd)
	if endIdx == -1 {
		// Marker was corrupted, remove from beginIdx to EOF
		return strings.TrimRight(content[:beginIdx], "\r\n") + "\n"
	}

	afterEnd := endIdx + len(markerEnd)
	prefix := content[:beginIdx]
	suffix := content[afterEnd:]

	res := strings.TrimRight(prefix, "\r\n")
	trimmedSuffix := strings.TrimLeft(suffix, "\r\n")
	if len(trimmedSuffix) > 0 {
		if len(res) > 0 {
			res += "\n"
		}
		res += trimmedSuffix
	}
	if len(res) > 0 && !strings.HasSuffix(res, "\n") {
		res += "\n"
	}
	return res
}
