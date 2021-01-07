/*
* Client for WebSocket VPN
 */
package webtunnelclientold

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
	wsconn        *websocket.Conn // Websocket connection.
	daemonUDPConn net.Conn        // Daemon UDP Interface.
	Error         chan error      // Channel to handle errors from goroutines.
	daemonRPCConn *rpc.Client     // Handle to Daemon's RPC interface.
}

func NewWebtunnelClient(serverIPPort string, wsDialer *websocket.Dialer, daemonPort int) (*WebtunnelClient, error) {

	// Initialize websocket connection.
	u := url.URL{Scheme: "wss", Host: serverIPPort, Path: "/ws"}
	wsconn, _, err := wsDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	// Establish conn. to clientDaemon RPC for configuration.
	client, err := rpc.DialHTTP("tcp", fmt.Sprintf("127.0.0.1:%d", daemonPort))
	if err != nil {
		return nil, err
	}
	// Establish conn. to clientDaemon for packet processing.
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", daemonPort))
	if err != nil {
		return nil, err
	}
	glog.V(1).Info("Connected to ClientDaemon.")

	return &WebtunnelClient{
		wsconn:        wsconn,
		daemonUDPConn: conn,
		Error:         make(chan error),
		daemonRPCConn: client,
	}, nil
}

func (w *WebtunnelClient) Start() error {

	err := w.setClientDaemonCfg()
	if err != nil {
		return err
	}
	go w.processNetPacket()
	go w.processWSPacket()
	go w.checkDaemonHealth()

	return nil
}

// setClientDaemonCfg retrieves the client configuration from server and sends to Net daemon.
func (w *WebtunnelClient) setClientDaemonCfg() error {
	// Get configuration from server.
	if err := w.wsconn.WriteMessage(websocket.TextMessage, []byte("getConfig")); err != nil {
		return err
	}
	cfg := &webtunnelcommon.ClientConfig{}
	if err := w.wsconn.ReadJSON(cfg); err != nil {
		return err
	}
	glog.V(1).Infof("Retrieved config from server %v", *cfg)

	// Send configuration to clientDaemon.
	args := InterfaceCfg{
		IP:          cfg.Ip,
		GWIP:        cfg.GWIp,
		Netmask:     cfg.Netmask,
		DNS:         cfg.DNS,
		RoutePrefix: cfg.RoutePrefix,
	}

	if err := w.daemonRPCConn.Call("NetIfce.SetInterfaceCfg", args, &struct{}{}); err != nil {
		return err
	}

	if err := w.daemonRPCConn.Call("NetIfce.SetRemote", w.daemonUDPConn.LocalAddr(), &struct{}{}); err != nil {
		return err
	}

	glog.V(1).Info("Daemon configured successfully")
	return nil
}

// CheckDaemonHealth pings the daemon and returns error if unreachable.
func (w *WebtunnelClient) checkDaemonHealth() {
	t := time.NewTicker(5 * time.Second)
	for {
		<-t.C
		if err := w.daemonRPCConn.Call("NetIfce.Ping", "hello", &struct{}{}); err != nil {
			w.Error <- fmt.Errorf("failed to reach Daemon %s. Try daemon restart", err)
			return
		}
	}
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

func (w *WebtunnelClient) processWSPacket() {
	for {
		mt, pkt, err := w.wsconn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return
			}
			w.Error <- fmt.Errorf("error reading websocket %s", err)
			return
		}
		if mt != websocket.BinaryMessage {
			glog.Warningf("Binary message type recvd from websocket")
			continue
		}
		webtunnelcommon.PrintPacketIPv4(pkt, "Client <- WebSocket")
		if _, err := w.daemonUDPConn.Write(pkt); err != nil {
			w.Error <- fmt.Errorf("error writing to daemon %s", err)
			return
		}
	}
}

func (w *WebtunnelClient) processNetPacket() {
	pkt := make([]byte, 2048)
	for {
		if _, err := w.daemonUDPConn.Read(pkt); err != nil {
			w.Error <- fmt.Errorf("error reading daemon %s", err)
			return
		}
		webtunnelcommon.PrintPacketIPv4(pkt, "Client <- NetDaemon")
		if err := w.wsconn.WriteMessage(websocket.BinaryMessage, pkt); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				return
			}
			w.Error <- fmt.Errorf("error writing to websocket: %s", err)
			return
		}
	}
}
