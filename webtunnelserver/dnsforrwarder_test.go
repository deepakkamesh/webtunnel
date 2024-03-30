package webtunnelserver

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestListenServ(t *testing.T) {
	dnsForwarder, err := NewDNSForwarder("127.0.0.1", 0)
	if err != nil {
		t.Error(err)
	}

	dnsForwarder.Start()
	defer dnsForwarder.Stop()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(dnsForwarder.handle.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	req := &layers.DNS{
		ID:     1234,
		QR:     false,
		OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{
			{Name: []byte("google-public-dns-a.google.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err = gopacket.SerializeLayers(buf, opts, req)
	if err != nil {
		t.Errorf("failed to serialize expected DNS request: %v", err)
	}

	_, err = conn.Write(buf.Bytes())
	if err != nil {
		t.Errorf("failed to send DNS request: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	pkt := make([]byte, 2048)
	_, err = conn.Read(pkt)
	if err != nil {
		t.Errorf("failed to get DNS reply: %v", err)
	}
	reply, ok := gopacket.NewPacket(pkt, layers.LayerTypeDNS, gopacket.Default).Layer(layers.LayerTypeDNS).(*layers.DNS)
	if !ok {
		t.Errorf("Not a valid DNS reply: %v", reply)
	}
	repIP := reply.Answers[0].IP
	if repIP.String() != "8.8.8.8" {
		t.Errorf("Wrong Google DNS IP resolved: %v", repIP)
	}

}
