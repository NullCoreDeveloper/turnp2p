package turn

import (
	"math/rand"

	"github.com/bogdanfinn/tls-client/profiles"
)

type Profile struct {
	UserAgent       string
	SecChUa         string
	SecChUaMobile   string
	SecChUaPlatform string
	ClientProfile   profiles.ClientProfile
}

// BrowserProfiles contains authentic User-Agent and Client-Hints pairings for bot bypass.
var BrowserProfiles = []Profile{
	// Windows Chrome 131
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		ClientProfile:   profiles.Chrome_131,
	},
	// Windows Chrome 124
	{
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="124", "Not_A Brand";v="99", "Google Chrome";v="124"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Windows"`,
		ClientProfile:   profiles.Chrome_124,
	},
	// macOS Chrome 131
	{
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"macOS"`,
		ClientProfile:   profiles.Chrome_131,
	},
	// Linux Chrome 124
	{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		SecChUa:         `"Chromium";v="124", "Not_A Brand";v="24", "Google Chrome";v="124"`,
		SecChUaMobile:   "?0",
		SecChUaPlatform: `"Linux"`,
		ClientProfile:   profiles.Chrome_124,
	},
}

// GetRandomProfile returns a randomized authentic browser profile.
func GetRandomProfile() Profile {
	return BrowserProfiles[rand.Intn(len(BrowserProfiles))]
}
