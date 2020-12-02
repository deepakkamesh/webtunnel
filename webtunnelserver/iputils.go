package webtunnelserver

import (
	"encoding/binary"
	"fmt"
	"net"
)

type IPPam struct {
	prefix      string
	allocations map[string]interface{}
	ip          net.IP
	ipnet       *net.IPNet
	net         net.IP
	bcast       net.IP
}

func NewIPPam(prefix string) (*IPPam, error) {

	ip, ipnet, err := net.ParseCIDR(prefix)
	if err != nil {
		return nil, err
	}

	// Get Network and broadcast addresses of prefix.
	bcast := lastAddr(ipnet)
	net := ip.Mask(ipnet.Mask)

	ippam := &IPPam{
		prefix:      prefix,
		allocations: make(map[string]interface{}),
		ip:          ip,
		ipnet:       ipnet,
		net:         net,
		bcast:       bcast,
	}

	// Allocate net and bcast addresses.
	ippam.allocations[bcast.String()] = struct{}{}
	ippam.allocations[net.String()] = struct{}{}

	return ippam, nil
}

func (i *IPPam) GetAllocatedCount() int {
	return len(i.allocations)
}

func (i *IPPam) AcquireIP(data interface{}) (string, error) {

	for ip := i.ip.Mask(i.ipnet.Mask); i.ipnet.Contains(ip); inc(ip) {
		if _, exist := i.allocations[ip.String()]; !exist {
			i.allocations[ip.String()] = data
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("IPs exhausted")
}

func (i *IPPam) GetData(ip string) (interface{}, error) {
	if _, exists := i.allocations[ip]; !exists {
		return nil, fmt.Errorf("IP not available")
	}
	return i.allocations[ip], nil
}

func (i *IPPam) ReleaseIP(ip string) error {

	if i.net.String() == ip || i.bcast.String() == ip {
		return fmt.Errorf("cannot release network or broadcast address")
	}

	if _, exists := i.allocations[ip]; !exists {
		return fmt.Errorf("IP not allocated")
	}
	delete(i.allocations, ip)
	return nil
}

func (i *IPPam) AcquireSpecificIP(ip string, data interface{}) error {
	if _, exists := i.allocations[ip]; exists {
		return fmt.Errorf("IP already in use")
	}
	i.allocations[ip] = data
	return nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func lastAddr(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP.To4()))
	binary.BigEndian.PutUint32(ip, binary.BigEndian.Uint32(n.IP.To4())|^binary.BigEndian.Uint32(net.IP(n.Mask).To4()))
	return ip
}
