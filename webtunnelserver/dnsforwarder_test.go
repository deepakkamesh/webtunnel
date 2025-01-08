package webtunnelserver

import (
	"fmt"
	"net"
	"strconv"
	"strings"
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

	dr := buildDNSRequest()
	_, err = conn.Write(dr)
	if err != nil {
		t.Errorf("failed to send DNS request: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	repIP, err := readDNSReply(conn)
	if err != nil {
		// check if it's because of Non Existent domain - we can ignore this
		// as this means the test environment is not processing DNS requests
		if strings.Contains(err, "Non-Existent domain") {
			return
		}
		t.Error(err)
	}
	if repIP.String() != "8.8.8.8" {
		t.Errorf("Wrong Google DNS IP resolved: %v", repIP)
	}

}

func readDNSReply(conn net.Conn) (net.IP, error) {
	pkt := make([]byte, 2048)
	_, err := conn.Read(pkt)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS reply: %v", err)
	}
	packet := gopacket.NewPacket(pkt, layers.LayerTypeDNS, gopacket.Default)
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil, fmt.Errorf("No DNS Layer")
	}
	reply, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return nil, fmt.Errorf("Not a valid DNS reply: %v", reply)
	}
	if len(reply.Answers) == 0 {
		return nil, fmt.Errorf("DNS reply has no answers: %v", reply)
	}
	repIP := reply.Answers[0].IP
	return repIP, nil
}

func buildDNSRequest() []byte {
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
	err := gopacket.SerializeLayers(buf, opts, req)
	if err != nil {
		panic(fmt.Sprintf("failed to serialize expected DNS request: %v", err))
	}
	return buf.Bytes()
}
