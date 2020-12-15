package webtunnelcommon

import (
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	DiagLevelInfo  = 1
	DiagLevelDebug = 2
)

type ClientConfig struct {
	Ip          string   `json:"ip"`          // IP address of client.
	RoutePrefix []string `json:"routeprefix"` // Network prefix to route.
	GWIp        string   `json:"gwip"`        // Gateway IP address.
}

func PrintPacketIPv4(pkt []byte, tag string) {
	glog.V(2).Infof("%s: %v", tag, gopacket.NewPacket(
		pkt,
		layers.LayerTypeIPv4,
		gopacket.Default,
	))
}
