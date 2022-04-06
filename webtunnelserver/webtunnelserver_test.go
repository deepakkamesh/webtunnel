package webtunnelserver

import (
	"flag"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/deepakkamesh/webtunnel/mocks"
	wc "github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

func TestServer(t *testing.T) {

	flag.Set("stderrthreshold", "INFO")
	flag.Set("v", "1")

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockInterface := mocks.NewMockInterface(mockCtrl)

	// Override for testing.
	NewWaterInterface = func(c water.Config) (wc.Interface, error) {
		return mockInterface, nil
	}
	InitTunnel = func(ifceName, tunIP, tunNetmask string) error {
		return nil
	}

	//  Test server init.
	mockInterface.EXPECT().Name().Return("virt0").AnyTimes()
	mockInterface.EXPECT().IsTAP().Return(false).AnyTimes()
	server, err := NewWebTunnelServer("127.0.0.1:8811", "192.168.0.1",
		"255.255.255.0", "192.168.0.0/24", []string{"1.1.1.1"}, []string{"1.1.1.0/24"}, false, "", "")
	if err != nil {
		glog.Fatalf("%s", err)
	}

	// Load packet to send to client.
	pkt := createIPv4Pkt(net.IP{1, 1, 1, 1}, net.IP{192, 168, 0, 2})
	mockInterface.EXPECT().Read(gomock.Any()).Return(len(pkt), nil).SetArg(0, pkt).AnyTimes()

	// Start Server.
	server.Start()
	time.Sleep(1 * time.Second)

	// Initialize a websocket client.
	u := url.URL{Scheme: "ws", Host: "127.0.0.1:8811", Path: "/ws"}
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Test Get config from server.
	if err = c.WriteMessage(websocket.TextMessage, []byte("getConfig user hostname")); err != nil {
		t.Error(err)
	}
	cfg := &wc.ClientConfig{}
	if err := c.ReadJSON(cfg); err != nil {
		t.Error(err)
	}

	allocations := server.DumpAllocations()
	data := allocations["192.168.0.2"]

	if data.username != "user" {
		t.Errorf("Expected user, got: %v", data.username)
	}

	if data.hostname != "hostname" {
		t.Errorf("Expected hostname, got: %v", data.hostname)
	}

	if cfg.IP != "192.168.0.2" {
		t.Errorf("config failed want 192.168.0.2, got %s", cfg.IP)
	}

	// Test packet from server -> client.
	_, b, err := c.ReadMessage()
	if err != nil {
		t.Error(err)
	}
	packet := gopacket.NewPacket(b, layers.LayerTypeIPv4, gopacket.Default)
	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !net.IP.Equal(ip.SrcIP, net.IP{1, 1, 1, 1}) {
		t.Errorf("Write failed: Got %v Expect %v", ip.SrcIP, net.IP{1, 1, 1, 1})
	}

	// Test packet from client -> server.
	mockInterface.EXPECT().Write([]byte{1, 3, 3}).Return(1, nil).Times(1)
	if err = c.WriteMessage(websocket.BinaryMessage, []byte{1, 3, 3}); err != nil {
		t.Error(err)
	}

	// Test User Metrics status
	metric := server.GetMetrics();
	if metric.MaxUsers != 253 {
		t.Errorf("MaxUsers expected: 253, got: %v",metric.MaxUsers)
	}
	if metric.Users != 1 {
		t.Errorf("Users expected: 1, got: %v",metric.Users)
	}

	// Close connection.
	err = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Second)
	c.Close()

	// Sleep for sometime to read all messages.
	ticker := time.NewTicker(1 * time.Second)
	select {
	case <-ticker.C:
		return
	case err := <-server.Error:
		t.Error(err)
	}
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
