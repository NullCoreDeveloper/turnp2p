package p2p

import (
	"testing"
)

func TestClassifyIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected IPClass
	}{
		{"255.255.255.255", IPClassBroadcast},
		{"10.42.255.255", IPClassBroadcast},
		{"10.42.1.255", IPClassUnicast},   // Not our /16 subnet broadcast
		{"224.0.0.251", IPClassMulticast}, // mDNS
		{"239.255.255.250", IPClassMulticast}, // SSDP
		{"10.42.0.5", IPClassUnicast},
		{"127.0.0.1", IPClassLocal},
		{"169.254.1.1", IPClassLocal},
		{"invalid_ip", IPClassUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := ClassifyIP(tt.ip)
			if got != tt.expected {
				t.Errorf("ClassifyIP(%q) = %v, want %v", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestRecalculateIPv4Checksum(t *testing.T) {
	// A valid ICMP echo request (ping) packet IP header
	packet := []byte{
		0x45, 0x00, 0x00, 0x54, 0x55, 0x76, 0x40, 0x00,
		0x40, 0x01, 0x00, 0x00, // Checksum field is zeroed here
		0x0a, 0x2a, 0x00, 0x05, // src: 10.42.0.5
		0x0a, 0x2a, 0x00, 0x06, // dst: 10.42.0.6
	}
	
	RecalculateIPv4Checksum(packet)

	// After recalculation, checksum should not be 0x0000
	if packet[10] == 0 && packet[11] == 0 {
		t.Errorf("Checksum was not updated")
	}

	expectedChecksum := uint16(packet[10])<<8 | uint16(packet[11])

	// Clear it and recalculate
	packet[10] = 0
	packet[11] = 0
	RecalculateIPv4Checksum(packet)
	newChecksum := uint16(packet[10])<<8 | uint16(packet[11])

	if expectedChecksum != newChecksum {
		t.Errorf("Checksum calculation is not deterministic")
	}
}
