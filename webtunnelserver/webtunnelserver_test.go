package webtunnelserver

import (
	"net/url"
	"testing"

	"github.com/deepakkamesh/webtunnel/mocks"
	wc "github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/golang/mock/gomock"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

/*
type waterTest struct {
	io.ReadWriteCloser
}

func (w waterTest) Name() string {
	return "virt0"
}

func (w waterTest) IsTAP() bool {
	return true
}

func (w waterTest) IsTUN() bool {
	return true
}*/

var mockInterface *mocks.MockInterface

func NewTestWaterInterface(c water.Config) (wc.Interface, error) {
	return mockInterface, nil
}

func TestServer(t *testing.T) {

	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockInterface = mocks.NewMockInterface(mockCtrl)
	mockInterface.EXPECT().Name().Return("virt0").AnyTimes()
	mockInterface.EXPECT().IsTAP().Return(false).AnyTimes()

	// Variables for NewTunn
	NewWaterInterface = NewTestWaterInterface
	initTunnel = initializeTestTunnel
	server, err := NewWebTunnelServer("127.0.0.1:8811", "192.168.0.1",
		"255.255.255.0", "192.168.0.0/24", []string{"1.1.1.1"}, []string{"1.1.1.1"}, "", "")
	if err != nil {
		glog.Fatalf("%s", err)
	}

	pkt := make([]byte, 2048)
	mockInterface.EXPECT().Read(pkt).Return(1, nil).AnyTimes()
	server.Start(false)

	// Write something.
	mockInterface.EXPECT().Write([]byte{1, 3, 3}).Return(1, nil).AnyTimes()
	if err := client([]byte{1, 3, 3}); err != nil {
		t.Error(err)
	}
	/*
		select {
		case err := <-server.Error:
			glog.Exitf("Shutting down server %v", err)
		}*/
}

func client(data []byte) error {
	u := url.URL{Scheme: "ws", Host: "127.0.0.1:8811", Path: "/ws"}
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	err = c.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return err
	}
	//fmt.Println("sds")
	/*_, message, err := c.ReadMessage()
	if err != nil {
		return err
	}
	//fmt.Println("sddds")
	if bytes.Compare(message, make([]byte, 2048)) == 0 {
		return fmt.Errorf("unexpected")
	}*/

	return nil
}

func New(config water.Config) (ifce wc.Interface, err error) {
	return nil, nil
}

func initializeTestTunnel(ifceName, tunIP, tunNetmask string) error {
	return nil
}
