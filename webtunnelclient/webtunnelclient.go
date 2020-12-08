/*
* Client for WebSocket VPN
 */
package webtunnelclient

import (
	"fmt"
	"net"
	"net/rpc"
	"net/url"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
)

type WebtunnelClient struct {
	Error            chan error      // Channel to get error messages.
	Diag             chan string     // Channel to get diagnostics messages.
	DiagLevel        int             // Enable diagnostics channel level. 0 none; 1 info 2 debug
	quitWSProcessor  chan struct{}   // Channel to handle shutdown websock processor.
	quitTUNProcessor chan struct{}   // Channel to handle shutdown Tunnel processor.
	wsconn           *websocket.Conn // Websocket connection.
	daemonConn       net.Conn        // Daemon UDP Interface.
	clientDaemonPort int             // Port number of Client Daemon.
}

func NewWebtunnelClient(DiagLevel int, serverIPPort string, wsDialer *websocket.Dialer, daemonPort int) (*WebtunnelClient, error) {

	// Initialize websocket connection.
	u := url.URL{Scheme: "wss", Host: serverIPPort, Path: "/ws"}
	wsconn, _, err := wsDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", daemonPort))
	if err != nil {
		return nil, err
	}

	err = setClientDaemonCfg(wsconn, daemonPort, conn.LocalAddr())
	if err != nil {
		return nil, err
	}

	return &WebtunnelClient{
		Error:            make(chan error),
		Diag:             make(chan string),
		DiagLevel:        DiagLevel,
		quitTUNProcessor: make(chan struct{}),
		quitWSProcessor:  make(chan struct{}),
		wsconn:           wsconn,
		daemonConn:       conn,
	}, nil
}

// setClientDaemonCfg retrieves the client configuration from server and sends to Net daemon.
func setClientDaemonCfg(conn *websocket.Conn, daemonPort int, addr net.Addr) error {
	// Get configuration from server.
	if err := conn.WriteMessage(websocket.TextMessage, []byte("getConfig")); err != nil {
		return err
	}
	cfg := &webtunnelcommon.ClientConfig{}
	if err := conn.ReadJSON(cfg); err != nil {
		return err
	}

	// Send configuration to clientDaemon.
	args := SetIPArgs{
		IP:   cfg.Ip,
		GWIP: cfg.GWIp,
	}
	client, err := rpc.DialHTTP("tcp", fmt.Sprintf("127.0.0.1:%d", daemonPort))
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.Call("NetIfce.SetIP", args, &struct{}{}); err != nil {
		return err
	}

	if err := client.Call("NetIfce.SetRoute", cfg.RoutePrefix, &struct{}{}); err != nil {
		return err
	}

	if err := client.Call("NetIfce.SetRemote", addr, &struct{}{}); err != nil {
		return err
	}

	return nil
}

func (w *WebtunnelClient) Start() {
	go w.ProcessNetPacket()
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
			if w.DiagLevel >= webtunnelcommon.DiagLevelDebug {
				w.Diag <- fmt.Sprintln("Client recv from WS:", gopacket.NewPacket(
					pkt,
					layers.LayerTypeIPv4,
					gopacket.Default,
				))
			}
			if _, err := w.daemonConn.Write(pkt); err != nil {
				w.Error <- fmt.Errorf("error writing to net daemon %s", err)
			}
		}
	}
}

func (w *WebtunnelClient) ProcessNetPacket() {
	pkt := make([]byte, 2000)
	for {
		select {
		case <-w.quitTUNProcessor:
			return

		default:
			if _, err := w.daemonConn.Read(pkt); err != nil {
				w.Error <- fmt.Errorf("error reading daemon %s", err)
			}
			if w.DiagLevel >= webtunnelcommon.DiagLevelDebug {
				w.Diag <- fmt.Sprintln("Client recv from Daemon:", gopacket.NewPacket(
					pkt,
					layers.LayerTypeIPv4,
					gopacket.Default,
				))
			}
			if err := w.wsconn.WriteMessage(websocket.BinaryMessage, pkt); err != nil {
				w.Error <- fmt.Errorf("error writing to websocket: %s", err)
			}
		}
	}
}
