package turn

import (
	"time"
)

// Credentials contains the extracted TURN credentials for VK calls.
type Credentials struct {
	Username    string    `json:"username"`
	Password    string    `json:"password"`
	ServerAddr  string    `json:"serverAddr"`
	ServerAddrs []string  `json:"serverAddrs"`
	WsEndpoint  string    `json:"wsEndpoint"`
	ExpiresAt   time.Time `json:"expiresAt"`
	Link        string    `json:"link"`
}

// VKCredentials contains client configuration for VK API apps.
type VKCredentials struct {
	ClientID     string
	ClientSecret string
	Name         string
}

// DefaultVKCredentials contains official VK applications credentials pool.
// Only apps that have access to calls.getAnonymousToken are included.
var DefaultVKCredentials = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2", Name: "VK_WEB_APP"},
	{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw", Name: "VK_MVK_APP"},
}
