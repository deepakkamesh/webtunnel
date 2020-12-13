/*
* Client for WebSocket VPN
 */
package webtunnelclient

import (
	"fmt"
	"net"
	"net/rpc"
	"net/url"
	"time"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/gorilla/websocket"
)

type WebtunnelClient struct {
	wsconn           *websocket.Conn // Websocket connection.
	daemonConn       net.Conn        // Daemon UDP Interface.
	clientDaemonPort int             // Port number of Client Daemon.
}

func NewWebtunnelClient(serverIPPort string, wsDialer *websocket.Dialer, daemonPort int) (*WebtunnelClient, error) {

	// Initialize websocket connection.
	u := url.URL{Scheme: "wss", Host: serverIPPort, Path: "/ws"}
	wsconn, _, err := wsDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	// Connect and initialize Daemon.
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", daemonPort))
	if err != nil {
		return nil, err
	}
	glog.V(1).Info("Connected to Daemon")

	err = setClientDaemonCfg(wsconn, daemonPort, conn.LocalAddr())
	if err != nil {
		return nil, err
	}

	return &WebtunnelClient{
		wsconn:     wsconn,
		daemonConn: conn,
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
	glog.V(1).Infof("Got config from server %v", *cfg)

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

	glog.V(1).Info("Daemon configured successfully")
	return nil
}

func (w *WebtunnelClient) Start() {
	go w.ProcessNetPacket()
	go w.ProcessWSPacket()
}

func (w *WebtunnelClient) Stop() error {
	err := w.wsconn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		return err
	}
	// Wait for some time for server to terminate conn before closing on client end.
	// Otherwise its seen as a abnormal closure and will result in error.
	time.Sleep(time.Second)
	w.wsconn.Close()
	return nil
}

func (w *WebtunnelClient) ProcessWSPacket() {
	for {
		mt, pkt, err := w.wsconn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return
			}
			glog.Fatalf("error reading websocket %s", err)
		}
		if mt != websocket.BinaryMessage {
			glog.Warningf("Binary message type recvd from websocket")
			continue
		}
		webtunnelcommon.PrintPacketIPv4(pkt, "Client <- WebSocket")
		if _, err := w.daemonConn.Write(pkt); err != nil {
			glog.Fatalf("error writing to daemon %s", err)
		}
	}
}

func (w *WebtunnelClient) ProcessNetPacket() {
	pkt := make([]byte, 2048)
	for {
		if _, err := w.daemonConn.Read(pkt); err != nil {
			glog.Fatalf("error reading daemon %s", err)
		}
		webtunnelcommon.PrintPacketIPv4(pkt, "Client <- NetDaemon")
		if err := w.wsconn.WriteMessage(websocket.BinaryMessage, pkt); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return
			}
			glog.Fatalf("error writing to websocket: %s", err)
		}
	}
}
