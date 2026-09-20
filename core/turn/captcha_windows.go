//go:build windows

package turn

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
}

func getBrowserCandidates() []string {
	var candidates []string
	progFiles := os.Getenv("ProgramFiles")
	progFilesX86 := os.Getenv("ProgramFiles(x86)")
	localAppData := os.Getenv("LOCALAPPDATA")

	// Standard installation paths for Chromium-based browsers on Windows
	paths := []string{
		filepath.Join(progFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(progFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(localAppData, "Microsoft", "Edge", "Application", "msedge.exe"),
		filepath.Join(progFiles, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(progFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(localAppData, "Google", "Chrome", "Application", "chrome.exe"),
		filepath.Join(localAppData, "Yandex", "YandexBrowser", "Application", "browser.exe"),
		filepath.Join(progFilesX86, "Yandex", "YandexBrowser", "Application", "browser.exe"),
		filepath.Join(progFiles, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
		filepath.Join(progFilesX86, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
	}

	for _, p := range paths {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				candidates = append(candidates, p)
			}
		}
	}

	// Fallback to PATH commands
	candidates = append(candidates, "msedge", "chrome", "brave")
	return candidates
}
