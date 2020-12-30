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
	Netmask     string   `json:"netmask"`     // Netmask of interface.
	RoutePrefix []string `json:"routeprefix"` // Network prefix to route.
	GWIp        string   `json:"gwip"`        // Gateway IP address.
	DNS         []string `json:"dns"`         // DNS IPs
}

func PrintPacketIPv4(pkt []byte, tag string) {
	packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
	if _, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		glog.V(2).Infof("%s: %v", tag, packet)
	}
}

func PrintPacketEth(pkt []byte, tag string) {
	packet := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
	if _, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		glog.V(2).Infof("%s: %v", tag, packet)
	}
}
