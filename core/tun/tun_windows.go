//go:build windows

package tun

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

//go:embed wintun_bin/wintun_amd64.dll
var wintunAmd64 []byte

//go:embed wintun_bin/wintun_arm64.dll
var wintunArm64 []byte

//go:embed wintun_bin/wintun_386.dll
var wintun386 []byte

func ensureWintunDLL() error {
	exePath, err := os.Executable()
	if err != nil {
		exePath = "."
	}
	exeDir := filepath.Dir(exePath)
	targetPath := filepath.Join(exeDir, "wintun.dll")

	// If wintun.dll already exists and is valid, return
	if info, err := os.Stat(targetPath); err == nil && info.Size() > 0 {
		return nil
	}

	var data []byte
	switch runtime.GOARCH {
	case "amd64":
		data = wintunAmd64
	case "arm64":
		data = wintunArm64
	case "386":
		data = wintun386
	default:
		return fmt.Errorf("unsupported Windows architecture for Wintun: %s", runtime.GOARCH)
	}

	if err := os.WriteFile(targetPath, data, 0755); err != nil {
		// Fallback to TEMP directory if exeDir is not writable
		tempPath := filepath.Join(os.TempDir(), "wintun.dll")
		if errTemp := os.WriteFile(tempPath, data, 0755); errTemp != nil {
			return fmt.Errorf("failed to extract wintun.dll to %s or %s: %w", targetPath, tempPath, err)
		}
	}
	return nil
}

type windowsDevice struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	name     string
	ip       string
	closed   atomic.Bool
}

func (d *windowsDevice) Read(p []byte) (int, error) {
	for !d.closed.Load() {
		packet, err := d.session.ReceivePacket()
		if err == nil {
			n := copy(p, packet)
			d.session.ReleaseReceivePacket(packet)
			return n, nil
		}

		event := d.session.ReadWaitEvent()
		res, _ := windows.WaitForSingleObject(event, 300)
		if res == windows.WAIT_OBJECT_0 {
			continue
		}
		if d.closed.Load() {
			return 0, io.EOF
		}
	}
	return 0, io.EOF
}

func (d *windowsDevice) Write(p []byte) (int, error) {
	if d.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	packet, err := d.session.AllocateSendPacket(len(p))
	if err != nil {
		return 0, err
	}
	copy(packet, p)
	d.session.SendPacket(packet)
	return len(p), nil
}

func (d *windowsDevice) Close() error {
	if d.closed.Swap(true) {
		return nil
	}
	// Clean up firewall rules
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name=TurnP2P-Mesh-Inbound").Run()
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name=TurnP2P-ICMPv4-Inbound").Run()

	d.session.End()
	return d.adapter.Close()
}

func (d *windowsDevice) Name() string {
	return d.name
}

func (d *windowsDevice) IP() string {
	return d.ip
}

// OpenDevice creates and configures a Wintun adapter on Windows with assigned virtual IP.
func OpenDevice(name string, virtualIP string) (Device, error) {
	if name == "" {
		name = "turnp2p0"
	}

	if err := ensureWintunDLL(); err != nil {
		return nil, fmt.Errorf("wintun dll initialization failed: %w", err)
	}

	// 1. Try to open existing adapter first, or create a new one
	adapter, err := wintun.OpenAdapter(name)
	if err != nil {
		adapter, err = wintun.CreateAdapter(name, "TurnP2P", nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create wintun adapter '%s' (Run as Administrator required): %w", name, err)
		}
	}

	// 2. Start ring-buffer session (0x800000 = 8MB capacity)
	session, err := adapter.StartSession(0x800000)
	if err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("failed to start wintun session: %w", err)
	}

	// 3. Configure IP and Subnet mask using netsh
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	cmdSetIP := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", name),
		"source=static",
		fmt.Sprintf("addr=%s", virtualIP),
		"mask=255.255.0.0",
		"gateway=none",
	)
	if out, err := cmdSetIP.CombinedOutput(); err != nil {
		log.Printf("[Wintun] netsh set address warning (%s): %v (output: %s)", virtualIP, err, string(out))
	}

	cmdSetMetric := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "interface",
		fmt.Sprintf("name=%s", name),
		"metric=1",
	)
	_ = cmdSetMetric.Run()

	cmdSetMTU := exec.CommandContext(ctx, "netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("name=%s", name),
		"mtu=1500",
		"store=persistent",
	)
	_ = cmdSetMTU.Run()

	// 4. Configure Windows Firewall and Network Profile
	// Set network category to Private so Windows treats turnp2p0 as a trusted local LAN
	cmdSetPrivate := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Get-NetConnectionProfile -InterfaceAlias '%s' | Set-NetConnectionProfile -NetworkCategory Private", name),
	)
	_ = cmdSetPrivate.Run()

	// Clean up old rules if exist
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name=TurnP2P-Mesh-Inbound").Run()
	_ = exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "delete", "rule", "name=TurnP2P-ICMPv4-Inbound").Run()

	// Allow all inbound traffic from TurnP2P subnet (10.42.0.0/16) across all profiles
	cmdAllowMesh := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name=TurnP2P-Mesh-Inbound",
		"dir=in",
		"action=allow",
		"remoteip=10.42.0.0/16",
		"enable=yes",
		"profile=any",
	)
	if out, err := cmdAllowMesh.CombinedOutput(); err != nil {
		log.Printf("[Wintun] firewall allow mesh warning: %v (out: %s)", err, string(out))
	}

	// Allow ICMPv4 (ping) from TurnP2P subnet
	cmdAllowICMP := exec.CommandContext(ctx, "netsh", "advfirewall", "firewall", "add", "rule",
		"name=TurnP2P-ICMPv4-Inbound",
		"dir=in",
		"action=allow",
		"protocol=icmpv4:8,any",
		"remoteip=10.42.0.0/16",
		"enable=yes",
		"profile=any",
	)
	_ = cmdAllowICMP.Run()

	dev := &windowsDevice{
		adapter: adapter,
		session: session,
		name:    name,
		ip:      virtualIP,
	}

	log.Printf("[Wintun] Adapter %s initialized with IP %s/16 (Firewall rules configured)", name, virtualIP)
	return dev, nil
}
