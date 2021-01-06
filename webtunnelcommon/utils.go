package webtunnelcommon

import (
	"crypto/rand"
	"net"

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

func GetMacbyName(name string) net.HardwareAddr {
	ints, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, i := range ints {
		if i.Name == name {
			return i.HardwareAddr
		}
	}
	return nil
}

// IsConfigured checks if interface ifName is configured with ip.
func IsConfigured(ifName string, ip string) bool {
	ints, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, i := range ints {
		if i.Name == ifName {
			ips, err := i.Addrs()
			if err != nil {
				return false
			}
			for _, ipAddr := range ips {
				ipA, _, _ := net.ParseCIDR(ipAddr.String())
				if ipA.String() == ip {
					return true
				}
			}
		}
	}
	return false
}

// Generate a random private MAC address for GW server to handle ARP etc.
func GenMACAddr() []byte {
	buf := make([]byte, 6)
	rand.Read(buf)
	// Set the local bit
	buf[0] = (buf[0] | 2) & 0xfe
	return buf
}
