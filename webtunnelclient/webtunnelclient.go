/*
* Client for WebSocket VPN
 */
package webtunnelclient

import (
	"crypto/tls"
	"fmt"
	"net/url"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

type WebtunnelClient struct {
	Error            chan error       // Channel to get error messages.
	Diag             chan string      // Channel to get diagnostics messages.
	DiagLevel        int              // Enable diagnostics channel level. 0 none; 1 info 2 debug
	quitWSProcessor  chan struct{}    // Channel to handle shutdown websock processor.
	quitTUNProcessor chan struct{}    // Channel to handle shutdown Tunnel processor.
	wsconn           *websocket.Conn  // Websocket connection.
	iconn            *water.Interface // Tunnel Interface.
}

func NewWebtunnelClient(DiagLevel int, serverIPPort string, tlsVerify bool) (*WebtunnelClient, error) {

	// Create TUN interface.
	iconn, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating TUN int %s", err)
	}

	// Initialize websocket connection.
	u := url.URL{Scheme: "wss", Host: serverIPPort, Path: "/ws"}
	wsDialer := websocket.Dialer{}
	wsDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: tlsVerify}
	wsconn, _, err := wsDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	cfg, err := getClientConfig(wsconn)
	if err != nil {
		return nil, err
	}

	// Assign IP to tunnel and setup routing; OS specific.
	if err := initializeTunnel(cfg.Ip, cfg.GWIp, iconn.Name(), cfg.RoutePrefix); err != nil {
		return nil, err
	}

	return &WebtunnelClient{
		Error:            make(chan error),
		Diag:             make(chan string),
		DiagLevel:        DiagLevel,
		quitTUNProcessor: make(chan struct{}),
		quitWSProcessor:  make(chan struct{}),
		wsconn:           wsconn,
		iconn:            iconn,
	}, nil
}

// getConfig retrieves the client configuration from server.
func getClientConfig(conn *websocket.Conn) (*webtunnelcommon.ClientConfig, error) {
	if err := conn.WriteMessage(websocket.TextMessage, []byte("getConfig")); err != nil {
		return nil, err
	}
	cfg := &webtunnelcommon.ClientConfig{}
	if err := conn.ReadJSON(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (w *WebtunnelClient) Start() {
	go w.ProcessTUNPacket()
	go w.ProcessWSPacket()
}

func (w *WebtunnelClient) Stop() error {
	w.quitTUNProcessor <- struct{}{}
	w.quitWSProcessor <- struct{}{}
	return nil
}

func (w *WebtunnelClient) ProcessWSPacket() {
	for {
		select {
		case <-w.quitWSProcessor:
			// TODO: Send Close control message.
			w.wsconn.Close()
			return

		default:
			mt, pkt, err := w.wsconn.ReadMessage()
			if err != nil {
				w.Error <- fmt.Errorf("error reading websocket %s", err)
			}
			if mt != websocket.BinaryMessage {
				w.Error <- fmt.Errorf("unknown websocket message type")
			}
			if _, err := w.iconn.Write(pkt); err != nil {
				w.Error <- fmt.Errorf("error writing to tunnel %s", err)
			}
			if w.DiagLevel >= webtunnelcommon.DiagLevelDebug {
				w.Diag <- fmt.Sprintln("recv from WS", gopacket.NewPacket(
					pkt,
					layers.LayerTypeIPv4,
					gopacket.Default,
				))
			}
		}
	}
}

func (w *WebtunnelClient) ProcessTUNPacket() {
	pkt := make([]byte, 2000)
	for {
		select {
		case <-w.quitTUNProcessor:
			return

		default:
			if _, err := w.iconn.Read(pkt); err != nil {
				w.Error <- fmt.Errorf("error reading tunnel %s", err)
			}
			if err := w.wsconn.WriteMessage(websocket.BinaryMessage, pkt); err != nil {
				w.Error <- fmt.Errorf("error writing to websocket: %s", err)
			}
			if w.DiagLevel >= webtunnelcommon.DiagLevelDebug {
				w.Diag <- fmt.Sprintln("recv from TUN", gopacket.NewPacket(
					pkt,
					layers.LayerTypeIPv4,
					gopacket.Default,
				))
			}
		}
	}
}
