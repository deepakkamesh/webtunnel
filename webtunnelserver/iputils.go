package webtunnelserver

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

const (
	ipStatusRequested = 1
	ipStatusInUse     = 2
)

type ipData struct {
	ipStatus int
	data     interface{}
}

type IPPam struct {
	prefix      string
	allocations map[string]*ipData
	ip          net.IP
	ipnet       *net.IPNet
	net         net.IP
	bcast       net.IP
	lock        sync.Mutex
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
		allocations: make(map[string]*ipData),
		ip:          ip,
		ipnet:       ipnet,
		net:         net,
		bcast:       bcast,
	}

	// Allocate net and bcast addresses.
	ippam.allocations[bcast.String()] = &ipData{ipStatus: ipStatusInUse}
	ippam.allocations[net.String()] = &ipData{ipStatus: ipStatusInUse}

	return ippam, nil
}

func (i *IPPam) GetAllocatedCount() int {
	return len(i.allocations)
}

// Acquire IP gets a free IP and marks the status as requested. SetIPactive should be called
// to make the IP active.
func (i *IPPam) AcquireIP(data interface{}) (string, error) {
	i.lock.Lock()
	defer i.lock.Unlock()

	for ip := i.ip.Mask(i.ipnet.Mask); i.ipnet.Contains(ip); inc(ip) {
		if _, exist := i.allocations[ip.String()]; !exist {
			i.allocations[ip.String()] = &ipData{
				ipStatus: ipStatusRequested,
				data:     data,
			}
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("IPs exhausted")
}

func (i *IPPam) SetIPActive(ip string) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	if _, exists := i.allocations[ip]; !exists {
		return fmt.Errorf("IP not available")
	}
	i.allocations[ip].ipStatus = ipStatusInUse
	return nil
}

func (i *IPPam) GetData(ip string) (interface{}, error) {
	i.lock.Lock()
	defer i.lock.Unlock()

	if v, exists := i.allocations[ip]; !exists || v.ipStatus != ipStatusInUse {
		return nil, fmt.Errorf("IP not available or not marked in use")
	}
	return i.allocations[ip].data, nil
}

func (i *IPPam) ReleaseIP(ip string) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	if i.net.String() == ip || i.bcast.String() == ip {
		return fmt.Errorf("cannot release network or broadcast address")
	}
	if _, exists := i.allocations[ip]; !exists {
		return fmt.Errorf("IP not allocated")
	}
	delete(i.allocations, ip)
	return nil
}

// Acquires specific IP and marks it as in use.
func (i *IPPam) AcquireSpecificIP(ip string, data interface{}) error {
	i.lock.Lock()
	defer i.lock.Unlock()

	if _, exists := i.allocations[ip]; exists {
		return fmt.Errorf("IP already in use")
	}
	i.allocations[ip] = &ipData{
		data:     data,
		ipStatus: ipStatusInUse,
	}
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
