package p2p

import (
	"net"
)

type IPClass int

const (
	IPClassUnicast IPClass = iota
	IPClassBroadcast
	IPClassMulticast
	IPClassLocal
	IPClassUnknown
)

// ClassifyIP determines the type of an IPv4 address for P2P mesh routing.
func ClassifyIP(ipStr string) IPClass {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return IPClassUnknown
	}
	ip = ip.To4()
	if ip == nil {
		return IPClassUnknown
	}

	if ip.IsMulticast() {
		return IPClassMulticast
	}

	if ip.Equal(net.IPv4bcast) { // 255.255.255.255
		return IPClassBroadcast
	}

	// Subnet broadcast for 10.42.0.0/16
	if ip[0] == 10 && ip[1] == 42 && ip[2] == 255 && ip[3] == 255 {
		return IPClassBroadcast
	}

	// Local/Loopback
	if ip[0] == 127 {
		return IPClassLocal
	}

	// Link-local
	if ip[0] == 169 && ip[1] == 254 {
		return IPClassLocal
	}

	return IPClassUnicast
}

// RecalculateIPv4Checksum updates the header checksum field in an IPv4 packet buffer.
func RecalculateIPv4Checksum(packet []byte) {
	if len(packet) < 20 {
		return
	}
	ihl := int(packet[0]&0x0F) * 4
	if len(packet) < ihl {
		return
	}
	
	packet[10] = 0
	packet[11] = 0
	
	var csum uint32
	for i := 0; i < ihl; i += 2 {
		csum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	csum = ^csum
	
	packet[10] = byte(csum >> 8)
	packet[11] = byte(csum)
}
