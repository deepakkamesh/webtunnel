package webtunnelclient

import (
	"bytes"
	"crypto/tls"
	"flag"
	"net"
	"testing"
	"time"

	"github.com/deepakkamesh/webtunnel/mocks"
	wc "github.com/deepakkamesh/webtunnel/webtunnelcommon"
	wts "github.com/deepakkamesh/webtunnel/webtunnelserver"
	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

func setupServerMocks(mockServerIfce *mocks.MockInterface) {
	mockServerIfce.EXPECT().Name().Return("virt0").AnyTimes()
	mockServerIfce.EXPECT().IsTAP().Return(false).AnyTimes()
	// Some test packets.
	srvPkt := createIPv4Pkt(net.IP{1, 2, 3, 1}, net.IP{192, 168, 0, 2})
	cliPkt := createIPv4Pkt(net.IP{1, 1, 1, 1}, net.IP{192, 168, 0, 2})

	// Load packet to send to client.
	mockServerIfce.EXPECT().Read(gomock.Any()).Return(len(srvPkt), nil).SetArg(0, srvPkt).AnyTimes()
	mockServerIfce.EXPECT().Write(cliPkt).Return(1, nil).AnyTimes()
}

func setupClientMocks(mockClientIfce *mocks.MockInterface) {
	mockClientIfce.EXPECT().Name().Return("virt0").AnyTimes()
	mockClientIfce.EXPECT().IsTAP().Return(false).AnyTimes()
	// Some test packets.
	srvPkt := createIPv4Pkt(net.IP{1, 2, 3, 1}, net.IP{192, 168, 0, 2})
	cliPkt := createIPv4Pkt(net.IP{1, 1, 1, 1}, net.IP{192, 168, 0, 2})
	// Load packet to send to server.
	mockClientIfce.EXPECT().Read(gomock.Any()).Return(len(cliPkt), nil).SetArg(0, cliPkt).AnyTimes()
	mockClientIfce.EXPECT().Write(srvPkt).Return(1, nil).AnyTimes()
}

// TestClient tests the client functionality by spinning up a test server and sending packets between them.
// This is an end 2 end test of the client and server.
func TestClient(t *testing.T) {

	flag.Set("stderrthreshold", "INFO")
	flag.Set("v", "1")

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	// ****** Start up a test server.
	mockServerIfce := mocks.NewMockInterface(mockCtrl)
	setupServerMocks(mockServerIfce)

	// Override server variables for testing.
	wts.NewWaterInterface = func(c water.Config) (wc.Interface, error) {
		return mockServerIfce, nil
	}
	wts.InitTunnel = func(ifceName, tunIP, tunNetmask string) error {
		return nil
	}

	//  Server init.
	server, err := wts.NewWebTunnelServer("127.0.0.1:8811", "192.168.0.1",
		"255.255.255.0", "192.168.0.0/24", []string{"8.8.1.1"}, []string{"1.1.1.0/24"}, false, "", "")
	if err != nil {
		t.Fatalf("%s %v", err, wts.InitTunnel("", "", ""))
	}

	server.Start()

	// Give server a bit to startup.
	time.Sleep(1 * time.Second)

	//****** Start a new client.
	mockClientIfce := mocks.NewMockInterface(mockCtrl)
	setupClientMocks(mockClientIfce)

	// Overrides for testing.
	NewWaterInterface = func(c water.Config) (wc.Interface, error) {
		return mockClientIfce, nil
	}
	IsConfigured = func(string, string) bool { return true }
	GetMacbyName = func(string) net.HardwareAddr {
		return net.HardwareAddr{0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	}
	dummyInitFunc := func(c *Interface) error {
		if bytes.Compare(c.IP, net.IP{192, 168, 0, 2}) > 0 {
			t.Errorf("Retrieve config: got: %s, expected:%s", c.IP, net.IP{192, 168, 0, 2})
		}
		return nil
	}

	// Client init.
	wsDialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client, err := NewWebtunnelClient("127.0.0.1:8811", &wsDialer,
		false, dummyInitFunc, false, 30)
	if err != nil {
		t.Fatal(err)
	}

	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	mockServerIfce.EXPECT().Close()
	server.Stop()
	// Some sleep to process the packets and stop gracefully
	time.Sleep(3 * time.Second)
}

func createIPv4Pkt(srcIP net.IP, dstIP net.IP) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.IPv4{
			SrcIP: srcIP,
			DstIP: dstIP,
		},
		&layers.TCP{},
		gopacket.Payload([]byte{1, 2, 3, 4}))
	return buf.Bytes()
}
