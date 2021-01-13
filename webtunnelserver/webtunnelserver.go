/*
webtunnelserver is the server side of webtunnel; a websocket based VPN server.
See examples for implementation.
*/
package webtunnelserver

import (
	"fmt"
	"log"
	"net/http"

	wc "github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

var InitTunnel = initializeTunnel            // (Overridable) OS specific initialization.
var NewWaterInterface = wc.NewWaterInterface // (Overridable) New initialized water interface.

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

type Metrics struct {
	Users   int // Total connected users.
	Packets int // total packets.
	Bytes   int // bytes pushed.
}

// WebTunnelServer represents a webtunnel server struct.
type WebTunnelServer struct {
	serverIPPort    string                     // IP Port for binding on server.
	ifce            wc.Interface               // Tunnel interface handle.
	conns           map[string]*websocket.Conn // Websocket connection.
	routePrefix     []string                   // Route prefix for client config.
	tunNetmask      string                     // Netmask for clients.
	clientNetPrefix string                     // IP range for clients.
	gwIP            string                     // Tunnel IP address of server.
	ipam            *IPPam                     // Client IP Address manager.
	httpsKeyFile    string                     // Key file for HTTPS.
	httpsCertFile   string                     // Cert file for HTTPS.
	Error           chan error                 // Channel to handle error from goroutine.
	dnsIPs          []string                   // DNS server IPs.
	metrics         *Metrics                   // Metrics.
	secure          bool                       // Start Server with https.

}

/*
NewWebTunnelServer returns an initialized webtunnel server.

serverIPPort: IP:Port to listen for websocket connections.

gwIP: TUN/TAP IP address of the server. Should be within clientNetPrefix (usually x.x.x.1).

tunNetmask: Network mask of the VPN network.

clientNetPrefix: Network prefix of the VPN network. (Used for IP address allocation)

dnsIPs: IP address of DNS servers (for client configuration)

routePrefix: Network prefix that the client should route via the tunnel.

secure: Start server in websocket secure.

httpsKeyFile: HTTPS Key File for secured connections.

httpsCertFile: HTTPS Cert file for secured connections.
*/
func NewWebTunnelServer(serverIPPort, gwIP, tunNetmask, clientNetPrefix string, dnsIPs []string,
	routePrefix []string, secure bool, httpsKeyFile string, httpsCertFile string) (*WebTunnelServer, error) {

	// Create TUN interface and initialize it.
	ifce, err := NewWaterInterface(water.Config{
		DeviceType: water.TUN,
	})

	if err != nil {
		return nil, fmt.Errorf("error creating TUN int %s", err)
	}
	if err := InitTunnel(ifce.Name(), gwIP, tunNetmask); err != nil {
		return nil, err
	}

	ipam, err := NewIPPam(clientNetPrefix)
	if err != nil {
		return nil, err
	}
	// Reserve the gateway IP from being given out.
	if err := ipam.AcquireSpecificIP(gwIP, struct{}{}); err != nil {
		return nil, err
	}
	return &WebTunnelServer{
		serverIPPort:    serverIPPort,
		ifce:            ifce,
		conns:           make(map[string]*websocket.Conn),
		routePrefix:     routePrefix,
		tunNetmask:      tunNetmask,
		clientNetPrefix: clientNetPrefix,
		gwIP:            gwIP,
		ipam:            ipam,
		httpsKeyFile:    httpsKeyFile,
		httpsCertFile:   httpsCertFile,
		Error:           make(chan error),
		dnsIPs:          dnsIPs,
		metrics:         &Metrics{},
		secure:          secure,
	}, nil
}

// Start the webtunnel server.
func (r *WebTunnelServer) Start() {

	// Start the HTTP Server.
	http.HandleFunc("/", r.httpEndpoint)
	http.HandleFunc("/ws", r.wsEndpoint)
	if r.secure {
		go func() { log.Fatal(http.ListenAndServeTLS(r.serverIPPort, r.httpsCertFile, r.httpsKeyFile, nil)) }()
	} else {
		go func() { log.Fatal(http.ListenAndServe(r.serverIPPort, nil)) }()
	}

	// Read and process packets from the tunnel interface.
	go r.processTUNPacket()
}

// Stop the webtunnel server.
func (r *WebTunnelServer) Stop() {
}

// processTUNPacket processes the packets read from tunnel.
func (r *WebTunnelServer) processTUNPacket() {
	defer func() { r.Error <- nil }()
	pkt := make([]byte, 2048)
	var oPkt []byte

	for {
		n, err := r.ifce.Read(pkt)
		if err != nil {
			r.Error <- fmt.Errorf("error reading from tunnel %s", err)
		}
		oPkt = pkt[:n]

		// Add to metrics.
		r.metrics.Bytes += n
		r.metrics.Packets++

		// Get dst IP and corresponding websocket connection.
		packet := gopacket.NewPacket(oPkt, layers.LayerTypeIPv4, gopacket.Default)
		ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		data, err := r.ipam.GetData(ip.DstIP.String())
		if err != nil {
			glog.V(2).Infof("unsolicited packet for IP:%v", ip.DstIP.String())
			continue
		}

		wc.PrintPacketIPv4(oPkt, "Server <- NetInterface")

		ws := data.(*websocket.Conn)
		if err := ws.WriteMessage(websocket.BinaryMessage, oPkt); err != nil {
			// Ignore close errors.
			if err == websocket.ErrCloseSent {
				continue
			}
			glog.Warningf("error writing to Websocket %s", err)
			continue
		}
	}
}

// wsEndpoint defines HTTP Websocket Path and upgrades the HTTP connection.
func (r *WebTunnelServer) wsEndpoint(w http.ResponseWriter, rcv *http.Request) {
	// Upgrade HTTP connection to a WebSocket connection.
	conn, err := upgrader.Upgrade(w, rcv, nil)
	if err != nil {
		glog.Errorf("Error upgrading to websocket: %s\n", err)
		return
	}
	defer conn.Close()

	// Get IP and add to ip management.
	ip, err := r.ipam.AcquireIP(conn)
	if err != nil {
		glog.Errorf("Error acquiring IP:%v", err)
		return
	}

	glog.V(1).Infof("New connection from %s", ip)

	// Process websocket packet.
	for {
		mt, message, err := conn.ReadMessage()
		if err != nil {
			r.ipam.ReleaseIP(ip)
			if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				glog.Infof("connection closed for %s", ip)
				return
			}
			glog.Warningf("error reading from websocket for %s: %s ", rcv.RemoteAddr, err)
			return
		}

		switch mt {
		case websocket.TextMessage: // Config message.
			if string(message) == "getConfig" {
				cfg := &wc.ClientConfig{
					Ip:          ip,
					Netmask:     r.tunNetmask,
					RoutePrefix: r.routePrefix,
					GWIp:        r.gwIP,
					DNS:         r.dnsIPs,
				}
				if err := conn.WriteJSON(cfg); err != nil {
					glog.Warningf("error sending config to client: %v", err)
					return
				}
				// Mark IP as in use so packets can be send to it. This is needed to avoid deadlock condition
				// when a client disconnects but still packets are available in buffer for its ip and a new
				// client acquires its ip it cannot get the config as the TUN writer is still busy trying to send
				// packets to it.
				if err := r.ipam.SetIPActive(ip); err != nil {
					glog.Errorf("Unable to mark IP %v in use", ip)
					return
				}
			}

		case websocket.BinaryMessage: // Packet message.
			wc.PrintPacketIPv4(message, "Server <- Websocket")
			n, err := r.ifce.Write(message)
			if err != nil {
				r.Error <- fmt.Errorf("error writing to tunnel %s", err)
			}
			// Add to metrics.
			r.metrics.Bytes += n
			r.metrics.Packets++
		}
	}
}

// httpEndpoint defines the HTTP / Path. The "Sender" will send an initial request to this URL.
func (r *WebTunnelServer) httpEndpoint(w http.ResponseWriter, rcv *http.Request) {
	fmt.Fprint(w, "OK")
}

// GetMetrics returns the current server metrics.
func (r *WebTunnelServer) GetMetrics() *Metrics {
	r.metrics.Users = r.ipam.GetAllocatedCount()
	return r.metrics
}

// ResetMetrics resets the metrics on the server.
func (r *WebTunnelServer) ResetMetrics() {
	r.metrics.Users = 0
	r.metrics.Packets = 0
	r.metrics.Bytes = 0
}
