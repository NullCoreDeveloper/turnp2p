package proxy

import (
	"testing"
)

func TestProxyManagerLifecycle(t *testing.T) {
	mgr := NewManager(nil)
	if mgr == nil {
		t.Fatal("failed to create manager")
	}

	rule := ForwardingRule{
		ID:         "rule-1",
		Name:       "Test HTTP",
		Protocol:   "TCP",
		LocalPort:  18080,
		RemoteIP:   "10.42.0.2",
		RemotePort: 80,
	}

	err := mgr.AddRule(rule)
	if err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	rules := mgr.ListRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	// Adding duplicate port should fail
	err = mgr.AddRule(rule)
	if err == nil {
		t.Fatal("expected error when adding rule with duplicate local port")
	}

	// Remove rule
	err = mgr.RemoveRule("rule-1")
	if err != nil {
		t.Fatalf("failed to remove rule: %v", err)
	}

	if len(mgr.ListRules()) != 0 {
		t.Fatalf("expected 0 rules after removal")
	}

	_ = mgr.Stop()
}
