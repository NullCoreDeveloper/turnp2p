//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// isElevated checks if the current process has Windows Administrator privileges.
func isElevated() bool {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	return token.IsElevated()
}

// ensureElevated restarts the current application with Administrator privileges via UAC ("runas")
// if it was launched without elevation.
func ensureElevated() bool {
	// If already elevated or already attempted, proceed normally
	if isElevated() {
		return true
	}

	for _, arg := range os.Args[1:] {
		if arg == "--elevated" {
			return true
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return true
	}

	cwd, _ := os.Getwd()

	verbPtr, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return true
	}
	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return true
	}
	cwdPtr, _ := windows.UTF16PtrFromString(cwd)

	var quotedArgs []string
	if len(os.Args) > 1 {
		for _, arg := range os.Args[1:] {
			if strings.Contains(arg, " ") {
				quotedArgs = append(quotedArgs, fmt.Sprintf(`"%s"`, arg))
			} else {
				quotedArgs = append(quotedArgs, arg)
			}
		}
	}
	quotedArgs = append(quotedArgs, "--elevated")
	args := strings.Join(quotedArgs, " ")

	argPtr, _ := windows.UTF16PtrFromString(args)

	err = windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, windows.SW_SHOWNORMAL)
	if err != nil {
		// If UAC was rejected or failed, continue in unprivileged (userspace) mode
		return true
	}

	// Elevated process launched successfully, terminate current unprivileged instance
	os.Exit(0)
	return true
}
