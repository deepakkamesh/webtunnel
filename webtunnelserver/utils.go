package webtunnelserver

const (
	DiagLevelInfo  = 1
	DiagLevelDebug = 2
)

type ClientConfig struct {
	Ip              string `json:"ip"`        // IP address of client.
	ClientNetPrefix string `json:"netprefix"` // Network prefix to route.
	GWIp            string `json:"gwip"`      // Gateway IP address.
}
