package turn

import (
	"math/rand"

	"github.com/bogdanfinn/tls-client/profiles"
)

type Profile struct {
	UserAgent           string
	SecChUa             string
	SecChUaMobile       string
	SecChUaPlatform     string
	Platform            string
	Languages           []string
	AcceptLanguage      string
	ScreenWidth         int
	ScreenHeight        int
	InnerWidth          int
	InnerHeight         int
	DevicePixelRatio    float64
	HardwareConcurrency int
	DeviceMemory        int
	IsMobile            bool
	ClientProfile       profiles.ClientProfile
}

// DesktopProfiles contains authentic User-Agent, headers, and device specs for desktop browsers.
var DesktopProfiles = []Profile{
	// Windows 11 Chrome 131
	{
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		SecChUa:             `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`,
		SecChUaMobile:       "?0",
		SecChUaPlatform:     `"Windows"`,
		Platform:            "Win32",
		Languages:           []string{"ru-RU", "ru", "en-US", "en"},
		AcceptLanguage:      "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		InnerWidth:          1920,
		InnerHeight:         969,
		DevicePixelRatio:    1.0,
		HardwareConcurrency: 8,
		DeviceMemory:        8,
		IsMobile:            false,
		ClientProfile:       profiles.Chrome_131,
	},
	// Windows 10 Chrome 124
	{
		UserAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		SecChUa:             `"Chromium";v="124", "Not_A Brand";v="99", "Google Chrome";v="124"`,
		SecChUaMobile:       "?0",
		SecChUaPlatform:     `"Windows"`,
		Platform:            "Win32",
		Languages:           []string{"ru-RU", "ru", "en-US", "en"},
		AcceptLanguage:      "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		InnerWidth:          1920,
		InnerHeight:         953,
		DevicePixelRatio:    1.0,
		HardwareConcurrency: 12,
		DeviceMemory:        16,
		IsMobile:            false,
		ClientProfile:       profiles.Chrome_124,
	},
	// Linux Chrome 124
	{
		UserAgent:           "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		SecChUa:             `"Chromium";v="124", "Not_A Brand";v="24", "Google Chrome";v="124"`,
		SecChUaMobile:       "?0",
		SecChUaPlatform:     `"Linux"`,
		Platform:            "Linux x86_64",
		Languages:           []string{"ru-RU", "ru", "en-US", "en"},
		AcceptLanguage:      "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		ScreenWidth:         1920,
		ScreenHeight:        1080,
		InnerWidth:          1920,
		InnerHeight:         982,
		DevicePixelRatio:    1.0,
		HardwareConcurrency: 8,
		DeviceMemory:        8,
		IsMobile:            false,
		ClientProfile:       profiles.Chrome_124,
	},
	// macOS Chrome 131
	{
		UserAgent:           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		SecChUa:             `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`,
		SecChUaMobile:       "?0",
		SecChUaPlatform:     `"macOS"`,
		Platform:            "MacIntel",
		Languages:           []string{"ru-RU", "ru", "en-US", "en"},
		AcceptLanguage:      "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		ScreenWidth:         1440,
		ScreenHeight:        900,
		InnerWidth:          1440,
		InnerHeight:         812,
		DevicePixelRatio:    2.0,
		HardwareConcurrency: 8,
		DeviceMemory:        8,
		IsMobile:            false,
		ClientProfile:       profiles.Chrome_131,
	},
}

// MobileProfiles contains authentic mobile device profiles (Android / Pixel / Samsung)
// specifically aligned with VK_MVK_APP (7879029).
var MobileProfiles = []Profile{
	// Android 14 Pixel 8
	{
		UserAgent:           "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.135 Mobile Safari/537.36",
		SecChUa:             `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`,
		SecChUaMobile:       "?1",
		SecChUaPlatform:     `"Android"`,
		Platform:            "Linux armv8l",
		Languages:           []string{"ru-RU", "ru", "en-US", "en"},
		AcceptLanguage:      "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		ScreenWidth:         412,
		ScreenHeight:        915,
		InnerWidth:          412,
		InnerHeight:         823,
		DevicePixelRatio:    2.625,
		HardwareConcurrency: 8,
		DeviceMemory:        8,
		IsMobile:            true,
		ClientProfile:       profiles.ConfirmedAndroid,
	},
	// Android 13 Samsung Galaxy S21
	{
		UserAgent:           "Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
		SecChUa:             `"Chromium";v="124", "Not_A Brand";v="99", "Google Chrome";v="124"`,
		SecChUaMobile:       "?1",
		SecChUaPlatform:     `"Android"`,
		Platform:            "Linux armv8l",
		Languages:           []string{"ru-RU", "ru", "en-US", "en"},
		AcceptLanguage:      "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
		ScreenWidth:         360,
		ScreenHeight:        800,
		InnerWidth:          360,
		InnerHeight:         740,
		DevicePixelRatio:    3.0,
		HardwareConcurrency: 8,
		DeviceMemory:        6,
		IsMobile:            true,
		ClientProfile:       profiles.ConfirmedAndroid2,
	},
}

// GetProfileForApp returns an authentic, fully matched browser profile tailored to the VK app type.
func GetProfileForApp(appName string) Profile {
	if appName == "VK_MVK_APP" || appName == "VK_MVK_VKVIDEO" {
		return MobileProfiles[rand.Intn(len(MobileProfiles))]
	}
	return DesktopProfiles[rand.Intn(len(DesktopProfiles))]
}

// GetRandomProfile returns a randomized authentic desktop browser profile.
func GetRandomProfile() Profile {
	return DesktopProfiles[rand.Intn(len(DesktopProfiles))]
}
