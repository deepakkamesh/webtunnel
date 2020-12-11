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

func (d *DNSForwarder) Start() error {
	go d.listenServ()
	return nil
}

func (d *DNSForwarder) listenServ() {
	pkt := make([]byte, 2048)
	for {

		_, peerAddr, err := d.handle.ReadFrom(pkt)
		if err != nil {
			glog.Error("error reading from net %v", err)
			return
		}

		dnsReq, ok := gopacket.NewPacket(pkt, layers.LayerTypeDNS, gopacket.Default).Layer(layers.LayerTypeDNS).(*layers.DNS)
		if !ok {
			glog.Warning("Not a valid DNS request")
			continue
		}

		hostname := string(dnsReq.Questions[0].Name)
		glog.Infof("Got from %v name resolution for %v", peerAddr, hostname)

		resp := &layers.DNS{}

		if err := validateReq(dnsReq); err != nil {
			glog.Warning("DNS request not supported")
			resp = buildResponse(dnsReq, nil, layers.DNSResponseCodeNotImp)
			continue
		}

		ips, err := net.LookupHost(hostname)

		if err != nil {
			glog.Warning("Unable to resolve %s", hostname)
			resp = buildResponse(dnsReq, nil, layers.DNSResponseCodeNotZone)
			continue
		}

		// All ok, build and send response.
		resp = buildResponse(dnsReq, ips, layers.DNSResponseCodeNoErr)

		buff := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		if err := resp.SerializeTo(buff, opts); err != nil {
			glog.Error("Error serializing %v", err)
		}

		if _, err := d.handle.WriteTo(buff.Bytes(), peerAddr); err != nil {
			glog.Errorf("Error writing response %v", err)
		}
	}
}

func validateReq(req *layers.DNS) error {
	if req.Questions[0].Type == layers.DNSTypeA || req.Questions[0].Class == layers.DNSClassIN {
		return nil
	}
	return fmt.Errorf("invalid request")
}

func buildResponse(req *layers.DNS, ips []string, respCode layers.DNSResponseCode) *layers.DNS {

	answers := []layers.DNSResourceRecord{}

	// Build answer struct for range of IPs.
	for _, v := range ips {
		ip, _, err := net.ParseCIDR(v + "/32")
		if err != nil {
			glog.Errorf("Unable to parse address %v", err)
			continue
		}
		answers = append(answers,
			layers.DNSResourceRecord{
				Name:  []byte(req.Questions[0].Name),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   600,
				IP:    ip,
			})
	}

	dns := layers.DNS{
		ID:     req.ID,
		QR:     true,
		OpCode: req.OpCode,

		AA: false,
		TC: false,
		RD: req.RD,
		RA: false,
		Z:  0,

		ResponseCode: respCode,
		ANCount:      1,
		Answers:      answers,
	}

	return &dns
}
