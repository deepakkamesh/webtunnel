/* webtunnelcommon package has common utils/structs for client/server */
package webtunnelcommon

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const (
	DiagLevelInfo  = 1
	DiagLevelDebug = 2
)

// ClientConfig represents the struct to pass config from server to client.
type ClientConfig struct {
	Ip          string   `json:"ip"`          // IP address of client.
	Netmask     string   `json:"netmask"`     // Netmask of interface.
	RoutePrefix []string `json:"routeprefix"` // Network prefix to route.
	GWIp        string   `json:"gwip"`        // Gateway IP address.
	DNS         []string `json:"dns"`         // DNS IPs
}

// PrintPacketIPv4 prints the IPv4 packet.
func PrintPacketIPv4(pkt []byte, tag string) {
	packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
	if _, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		glog.V(2).Infof("%s: %v", tag, packet)
	}
}

// PrintPacketEth prints the Ethernet packet.
func PrintPacketEth(pkt []byte, tag string) {
	packet := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
	if _, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		glog.V(2).Infof("%s: %v", tag, packet)
	}
}

// GetIntCfg returns the hardware address and IPs for the interface.
func GetIntCfg(name string) (net.HardwareAddr, []net.IP, error) {
	ints, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, i := range ints {
		if i.Name == name {
			netA, err := i.Addrs()
			if err != nil {
				return nil, nil, err
			}
			var ips []net.IP
			for _, ipAddr := range netA {
				ipA, _, _ := net.ParseCIDR(ipAddr.String())
				ips = append(ips, ipA)
			}
			return i.HardwareAddr, ips, nil
		}
	}
	return nil, nil, fmt.Errorf("not found")
}

// Get the mac address of the interface by name. eg. eth0.
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
func GenMACAddr() net.HardwareAddr {
	buf := make([]byte, 6)
	rand.Read(buf)
	// Set the local bit
	buf[0] = (buf[0] | 2) & 0xfe
	return buf
}
