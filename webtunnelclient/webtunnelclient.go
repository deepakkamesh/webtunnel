/*
* Client for WebSocket VPN
 */
package webtunnelclient

import (
	"fmt"
	"net/url"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

type WebtunnelClient struct {
	Error            chan error       // Channel to get error messages.
	Diag             chan string      // Channel to get packet diagnostics.
	enDiag           bool             // Enable packet diagnostics channel.
	quitWSProcessor  chan struct{}    // Channel to handle shutdown websock processor.
	quitTUNProcessor chan struct{}    // Channel to handle shutdown Tunnel processor.
	wsconn           *websocket.Conn  // Websocket connection.
	iconn            *water.Interface //Tunnel Interface.
}

func NewWebtunnelClient(enDiag bool, serverIPPort string, routePrefix string) (*WebtunnelClient, error) {

	// Create TUN interface.
	iconn, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating TUN int %s", err)
	}

	// Assign IP to tunnel and setup routing; OS specific.
	if err := initializeTunnel("10.0.0.2", "10.0.0.1", iconn.Name(), routePrefix); err != nil {
		return nil, err
	}

	// Initialize websocket connection.
	u := url.URL{Scheme: "ws", Host: serverIPPort, Path: "/ws"}
	wsconn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	return &WebtunnelClient{
		Error:            make(chan error),
		Diag:             make(chan string),
		enDiag:           enDiag,
		quitTUNProcessor: make(chan struct{}),
		quitWSProcessor:  make(chan struct{}),
		wsconn:           wsconn,
		iconn:            iconn,
	}, nil
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
			if w.enDiag {
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
			if w.enDiag {
				w.Diag <- fmt.Sprintln("recv from TUN", gopacket.NewPacket(
					pkt,
					layers.LayerTypeIPv4,
					gopacket.Default,
				))
			}
		}
	}
}
