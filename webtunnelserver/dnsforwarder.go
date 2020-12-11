package webtunnelserver

import (
	"fmt"
	"net"

	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type DNSForwarder struct {
	handle *net.UDPConn
}

func NewDNSForwarder(ip string, port int) (*DNSForwarder, error) {

	h, err := net.ListenUDP("udp", &net.UDPAddr{Port: port, IP: net.ParseIP(ip)})
	if err != nil {
		return nil, err
	}

	return &DNSForwarder{
		handle: h,
	}, nil
}

func (d *DNSForwarder) Start() {
	go d.listenServ()
}

func (d *DNSForwarder) listenServ() {
	pkt := make([]byte, 2048)
	for {

		_, peerAddr, err := d.handle.ReadFrom(pkt)
		if err != nil {
			glog.Errorf("error reading from net %v", err)
			return
		}

		// Verify if packet is valid DNS request.
		dnsReq, ok := gopacket.NewPacket(pkt, layers.LayerTypeDNS, gopacket.Default).Layer(layers.LayerTypeDNS).(*layers.DNS)
		if !ok {
			glog.Warning("Not a valid DNS request")
			continue
		}

		hostname := string(dnsReq.Questions[0].Name)
		glog.Infof("Got from %v name resolution for %v", peerAddr, hostname)

		// Only respond for support use cases.
		if err := validateReq(dnsReq); err != nil {
			glog.Warning("DNS request not supported")
			if err := d.sendResponse(dnsReq, peerAddr, nil, layers.DNSResponseCodeNotImp); err != nil {
				glog.Errorf("Error sending DNS response %v", err)
				return
			}
			continue
		}

		// Try to lookup hostname.
		ips, err := net.LookupHost(hostname)
		if err != nil {
			glog.Warningf("Unable to resolve %v", hostname)
			if err := d.sendResponse(dnsReq, peerAddr, nil, layers.DNSResponseCodeNXDomain); err != nil {
				glog.Errorf("Error sending DNS response %v", err)
				return
			}
			continue
		}

		// All ok, build and send response.
		if err := d.sendResponse(dnsReq, peerAddr, ips, layers.DNSResponseCodeNoErr); err != nil {
			glog.Errorf("Error sending DNS response %v", err)
			return
		}
	}
}

func validateReq(req *layers.DNS) error {
	if req.Questions[0].Type == layers.DNSTypeA || req.Questions[0].Class == layers.DNSClassIN {
		return nil
	}
	return fmt.Errorf("invalid request")
}

func (d *DNSForwarder) sendResponse(req *layers.DNS, peerAddr net.Addr, ips []string, respCode layers.DNSResponseCode) error {

	answers := []layers.DNSResourceRecord{}
	ancount := 0

	// Build answer struct for range of IPs.
	for _, v := range ips {
		ip, _, err := net.ParseCIDR(v + "/32")
		if err != nil {
			glog.Errorf("Unable to parse address %v", err)
			continue
		}
		// Return only IPv4 answers.
		if ip.To4() == nil {
			continue
		}
		answers = append(answers,
			layers.DNSResourceRecord{
				Name:  []byte(req.Questions[0].Name),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   4,
				IP:    ip,
			})
		ancount++
	}

	dns := layers.DNS{
		ID:     req.ID,     // Request ID; returned as is in response.
		QR:     true,       // Query Response flag.
		OpCode: req.OpCode, // OPCode; returned as is in response.

		AA: false,  // Authoritative Answer.
		TC: false,  // Truncation flag.
		RD: req.RD, // Recursion Desired.
		RA: false,  // Recursion Available.
		Z:  0,      // Reserved.

		ResponseCode: respCode,
		ANCount:      uint16(ancount),
		Answers:      answers,
	}

	// Send Response.
	buff := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := dns.SerializeTo(buff, opts); err != nil {
		return fmt.Errorf("Error serializing DNS response %v", err)
	}

	if _, err := d.handle.WriteTo(buff.Bytes(), peerAddr); err != nil {
		return fmt.Errorf("Error writing response to interface %v", err)
	}

	return nil
}
