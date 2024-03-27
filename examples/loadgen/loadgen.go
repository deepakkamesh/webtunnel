// loadgen.go Runs multiple client connection to server to simulate multi client connections. Useful to test load
// on server.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
	wc "github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

type fakeIterface struct {
	SrcIP *net.IP
}

func (i *fakeIterface) Name() string {
	return "fake0"
}
func (i *fakeIterface) IsTUN() bool {
	return true
}
func (i *fakeIterface) IsTAP() bool {
	return false
}
func (i *fakeIterface) Write(d []byte) (int, error) {
	return 1, nil
}
func (i *fakeIterface) Read(d []byte) (int, error) {
	// Generate a icmp packet for traffic
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts,
		&layers.IPv4{
			SrcIP:    *i.SrcIP, //net.IP{192, 168, 0, 2},
			DstIP:    net.IP{192, 168, 0, 1},
			Protocol: layers.IPProtocolICMPv4,
			Version:  4,
		},
		&layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		},
	)
	copy(d, buf.Bytes())
	time.Sleep(10 * time.Millisecond)
	return 1, nil
}
func (i *fakeIterface) Close() error {
	return nil
}

func main() {
	flag.Parse()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	glog.Infof("Starting WebTunnel Generator...")
	wsDialer := websocket.Dialer{}
	wsDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	var clients []*webtunnelclient.WebtunnelClient

	for i := 0; i < 200; i++ {
		SrcIP := make(net.IP, 1)
		dummyInitFunc := func(c *webtunnelclient.Interface) error {
			SrcIP = c.IP
			return nil
		}
		webtunnelclient.NewWaterInterface = func(c water.Config) (wc.Interface, error) {
			return &fakeIterface{
				SrcIP: &SrcIP,
			}, nil
		}
		webtunnelclient.IsConfigured = func(string, string) bool { return true }
		webtunnelclient.GetMacbyName = func(string) net.HardwareAddr {
			return net.HardwareAddr{0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
		}

		client, err := webtunnelclient.NewWebtunnelClient("192.168.1.117:8811", &wsDialer,
			false, dummyInitFunc, true, 30)
		clients = append(clients, client)
		if err != nil {
			glog.Exitf("Failed to initialize client: %s", err)
		}
		if err := client.Start(); err != nil {
			glog.Exit(err)
		}
		fmt.Println("New conn", i)
		time.Sleep(1 * time.Second)
	}
	select {
	case <-c:
		for _, client := range clients {
			client.Stop()
		}
		glog.Infoln("Shutting down WebTunnel")
		//	case err := <-client.Error:
		//	glog.Exitf("Client failure: %s", err)
	}

}
