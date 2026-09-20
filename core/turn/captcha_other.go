//go:build !windows

package turn

import (
	"os/exec"
	"runtime"
)

func setSysProcAttr(cmd *exec.Cmd) {}

func getBrowserCandidates() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{"chromium", "google-chrome", "chrome", "chromium-browser"}
	case "darwin":
		return []string{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "chromium"}
	default:
		return []string{"chromium", "chrome"}
	}
}
