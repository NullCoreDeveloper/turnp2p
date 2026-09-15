package turn

import (
	"time"
)

// Credentials contains the extracted TURN credentials for VK calls.
type Credentials struct {
	Username   string    `json:"username"`
	Password   string    `json:"password"`
	ServerAddr string    `json:"serverAddr"`
	WsEndpoint string    `json:"wsEndpoint"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Link       string    `json:"link"`
}

// VKCredentials contains client configuration for VK API apps.
type VKCredentials struct {
	ClientID     string
	ClientSecret string
	Name         string
}

// DefaultVKCredentials contains official VK applications credentials pool.
var DefaultVKCredentials = []VKCredentials{
	{ClientID: "6287487", ClientSecret: "QbYic1K3lEV5kTGiqlq2", Name: "VK_WEB_APP"},
	{ClientID: "7879029", ClientSecret: "aR5NKGmm03GYrCiNKsaw", Name: "VK_MVK_APP"},
	{ClientID: "52461373", ClientSecret: "o557NLIkAErNhakXrQ7A", Name: "VK_WEB_VKVIDEO"},
	{ClientID: "52649896", ClientSecret: "WStp4ihWG4l3nmXZgIbC", Name: "VK_MVK_VKVIDEO"},
	{ClientID: "51781872", ClientSecret: "IjjCNl4L4Tf5QZEXIHKK", Name: "VK_ID_AUTH"},
}
