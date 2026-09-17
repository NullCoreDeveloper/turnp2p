//go:build !windows

package main

// ensureElevated is a no-op on non-Windows platforms.
func ensureElevated() bool {
	return true
}
