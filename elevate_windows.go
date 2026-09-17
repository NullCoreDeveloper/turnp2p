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
	if isElevated() {
		return true
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

	var args string
	if len(os.Args) > 1 {
		var quotedArgs []string
		for _, arg := range os.Args[1:] {
			if strings.Contains(arg, " ") {
				quotedArgs = append(quotedArgs, fmt.Sprintf(`"%s"`, arg))
			} else {
				quotedArgs = append(quotedArgs, arg)
			}
		}
		args = strings.Join(quotedArgs, " ")
	}

	var argPtr *uint16
	if args != "" {
		argPtr, _ = windows.UTF16PtrFromString(args)
	}

	err = windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, windows.SW_SHOWNORMAL)
	if err != nil {
		// User declined UAC prompt or ShellExecute failed
		os.Exit(1)
		return false
	}

	// Elevated process launched successfully, terminate current unprivileged instance
	os.Exit(0)
	return true
}
