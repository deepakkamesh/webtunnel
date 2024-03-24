/*
Package webtunnelserver is the server side of webtunnel; a websocket based VPN server.
See examples for implementation.
*/
package webtunnelserver

import (
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	wc "github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

// InitTunnel (Overridable) OS specific initialization.
var InitTunnel = initializeTunnel

// NewWaterInterface (Overridable) New initialized water interface.
var NewWaterInterface = wc.NewWaterInterface

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

// Metrics is the system metrics structure.
type Metrics struct {
	Users    int // Total connected users.
	MaxUsers int // Maximum users supported by endpoint.
	Packets  int // total packets.
	Bytes    int // bytes pushed.
}

// WebTunnelServer represents a webtunnel server struct.
type WebTunnelServer struct {
	serverIPPort       string                     // IP Port for binding on server.
	ifce               wc.Interface               // Tunnel interface handle.
	conns              map[string]*websocket.Conn // Websocket connection.
	routePrefix        []string                   // Route prefix for client config.
	tunNetmask         string                     // Netmask for clients.
	clientNetPrefix    string                     // IP range for clients.
	gwIP               string                     // Tunnel IP address of server.
	ipam               *IPPam                     // Client IP Address manager.
	httpsKeyFile       string                     // Key file for HTTPS.
	httpsCertFile      string                     // Cert file for HTTPS.
	Error              chan error                 // Channel to handle error from goroutine.
	dnsIPs             []string                   // DNS server IPs.
	metrics            *Metrics                   // Metrics.
	secure             bool                       // Start Server with https.
	customHTTPHandlers map[string]http.Handler    // Array of custom HTTP handlers.
	metricsLock        sync.Mutex                 // Mutex for metrics write
	connMapLock        sync.Mutex                 // Mutex for Connection Map
	turnOff            bool                       // Flag to signal server should shutdown
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
		serverIPPort:       serverIPPort,
		ifce:               ifce,
		conns:              make(map[string]*websocket.Conn),
		routePrefix:        routePrefix,
		tunNetmask:         tunNetmask,
		clientNetPrefix:    clientNetPrefix,
		gwIP:               gwIP,
		ipam:               ipam,
		httpsKeyFile:       httpsKeyFile,
		httpsCertFile:      httpsCertFile,
		Error:              make(chan error),
		dnsIPs:             dnsIPs,
		metrics:            &Metrics{},
		secure:             secure,
		customHTTPHandlers: make(map[string]http.Handler),
		turnOff:            false,
	}, nil
}

// SetCustomHandler sets any custom http end point handler. This should be called prior to Start.
func (r *WebTunnelServer) SetCustomHandler(endpoint string, h http.Handler) error {
	if endpoint == "/ws" {
		return fmt.Errorf("cannot override ws handler")
	}
	r.customHTTPHandlers[endpoint] = h
	return nil
}

// Start the webtunnel server.
func (r *WebTunnelServer) Start() {

	// Start the HTTP Server.
	http.HandleFunc("/", r.httpEndpoint)
	http.HandleFunc("/ws", r.wsEndpoint)
	http.HandleFunc("/metrichealthz", r.healthEndpoint)
	http.HandleFunc("/metricvarz", r.metricEndpoint)

	// Start the custom handlers.
	for e, h := range r.customHTTPHandlers {
		http.Handle(e, h)
	}

	if r.secure {
		go func() { log.Fatal(http.ListenAndServeTLS(r.serverIPPort, r.httpsCertFile, r.httpsKeyFile, nil)) }()
	} else {
		go func() { log.Fatal(http.ListenAndServe(r.serverIPPort, nil)) }()
	}

	// Initialise some Metrics
	r.metrics.MaxUsers = getMaxUsers(r.clientNetPrefix)

	// Read and process packets from the tunnel interface.
	go r.processTUNPacket()

	// Routinely sends Ping packets to the Websocket interface.
	// Used to calculate clients average latency.
	go r.processPings()
}

// Stop the webtunnel server gracefully.
// All Websocket connections with peer will be terminated
// The tun interface handle will be closed
//
//	and this will eventually send nil to r.Error to let
//
// the Server Caller that the whole serving process is ended
func (r *WebTunnelServer) Stop() {
	r.turnOff = true

}

// PongHandler handles the pong messages from a client
func (r *WebTunnelServer) PongHandler(ip string) func(string) error {
	return func(aStr string) error {
		bt := []byte(aStr)
		val, _ := binary.Varint(bt)
		glog.V(2).Infof("Client %v answered, nano diff is %v", ip, val)
		return nil
	}
}

// processPings() processes the websocket pings sent from the server to the client
// Those are used to measure the latency seen with the clients.
func (r *WebTunnelServer) processPings() {
	// Small delay before sending pings
	glog.Info("Pings processing routine active")
	time.Sleep(60 * time.Second)
	for {
		if r.turnOff {
			return
		}
		glog.V(1).Info("Iterating among connections for Pings")
		r.connMapLock.Lock()
		for ip, wsConn := range r.conns {
			// Send ping (Pong handler was setup soon after when wsConn was created)
			buf := make([]byte, binary.MaxVarintLen64)
			tV := time.Now().UTC().UnixNano()
			binary.PutVarint(buf, tV)
			// pings sent have a deadline of 5 seconds
			if err := wsConn.WriteControl(websocket.PingMessage, buf, time.Now().Add(time.Duration(5*time.Second))); err != nil {
				glog.Warningf("issue sending ping to %v, reason: %v", ip, err)
			} else {
				glog.V(2).Infof("Ping sent to %v", ip)
			}
		}
		r.connMapLock.Unlock()
		glog.V(1).Info("Waiting 60 seconds before next ping batch")
		time.Sleep(60 * time.Second)
	}
}

// processTUNPacket processes the packets read from tunnel.
// Packets read from the TUN interface have to be forwarded to the
// relevant client via the appropriate websocket connection.
func (r *WebTunnelServer) processTUNPacket() {
	defer func() { r.Error <- nil }()
	pkt := make([]byte, 2048)
	var oPkt []byte

	for {
		select {
		case <-r.shutTunProcess:
			for ip, wsConn := range r.conns {
				err := wsConn.Close()
				if err != nil {
					glog.Errorf("client %v close issue when shutting TUN process: %v", ip, err)
				}
			}
			err := r.ifce.Close()
			if err != nil {
				glog.Errorf("interface close issue when shutting TUN process", err)
			}
			return
		default:
		}

		n, err := r.ifce.Read(pkt)
		if err != nil {
			r.Error <- fmt.Errorf("error reading from tunnel %s", err)
		}
		oPkt = pkt[:n]

		r.updateMetricsForPacket(n)

		// Get dst IP and corresponding websocket connection.
		packet := gopacket.NewPacket(oPkt, layers.LayerTypeIPv4, gopacket.Default)
		ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		ipDest := ip.DstIP.String()
		data, err := r.ipam.GetData(ipDest) // data is the connection object linked to the IP
		if err != nil {
			glog.Warningf("unsolicited packet for IP:%v", ipDest)
			continue
		}

		wc.PrintPacketIPv4(oPkt, "Server <- NetInterface")

		ws := data.(*websocket.Conn)
		r.connMapLock.Lock()
		if _, ok := r.conns[ipDest]; !ok {
			r.conns[ipDest] = ws
		}
		r.connMapLock.Unlock()
		if err := ws.WriteMessage(websocket.BinaryMessage, oPkt); err != nil {
			// Ignore close errors.
			if err == websocket.ErrCloseSent {
				glog.V(2).Info("ErrCloseSent")
				continue
			}
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				glog.V(2).Info("writing to Closed or Shutting down Websocket")
				continue
			}
			glog.Warningf("error writing to Websocket for ip: %s, %s", ipDest, err)
			continue
		}
	}
}

// releaseIP removes an ip from the connection tracking manager and connection map
func (r *WebTunnelServer) releaseIP(ip string) {
	r.ipam.ReleaseIP(ip)
	r.connMapLock.Lock()
	delete(r.conns, ip)
	r.connMapLock.Unlock()
}

// wsEndpoint defines HTTP Websocket Path and upgrades the HTTP connection.
// Websocket packets are then processed as they arrive.
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

	// Create Pong Handler to handle Pings
	conn.SetPongHandler(r.PongHandler(ip))

	// Process websocket packet.
	for {
		if r.turnOff {
			return
		}
		mt, message, err := conn.ReadMessage()
		if err != nil {
			userinfo, _ := r.ipam.GetUserinfo(ip)

			r.releaseIP(ip)

			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				glog.V(1).Infof("connection gracefuly closed for %s", ip)
				return
			}
			glog.Warningf("error reading from websocket, client info: %s@%s client ip: %s, origin:%s, reason: %s",
				userinfo.username, userinfo.hostname, ip, rcv.RemoteAddr, err)
			return
		}

		switch mt {
		case websocket.TextMessage: // Config or Command message.
			err := r.processIncomingTextMessage(conn, ip, message)
			if err != nil {
				r.Error <- fmt.Errorf("error processing Config/Command %s", err)
			}
		case websocket.BinaryMessage: // Packet message.
			err := r.processIncomingBinaryMessage(message)
			if err != nil {
				r.Error <- fmt.Errorf("error writing Binary to tunnel %s", err)
			}
		}

	}
}

// processIncomingTextMessage process Config and Command packets coming from the websocket
// since it is assumed we are receiving IP packets we just send them directly
// to the tun interface for the OS to route those
func (r *WebTunnelServer) processIncomingTextMessage(conn *websocket.Conn, ip string, message []byte) error {
	msg := strings.Split(string(message), " ")
	if msg[0] == "getConfig" {
		var username, hostname string
		if len(msg) != 3 {
			glog.Warningf("Cannot process username and hostname - using defaults")
			username = "guest"
			hostname = "workstation"
		} else {
			username = msg[1]
			hostname = msg[2]
		}

		serverHostname, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("Could not get hostname: %v", err)
		}

		glog.Infof("Config request from %s@%s", username, hostname)

		cfg := &wc.ClientConfig{
			IP:          ip,
			Netmask:     r.tunNetmask,
			RoutePrefix: r.routePrefix,
			GWIp:        r.gwIP,
			DNS:         r.dnsIPs,
			ServerInfo:  &wc.ServerInfo{Hostname: serverHostname},
		}
		if err := conn.WriteJSON(cfg); err != nil {
			return fmt.Errorf("error sending config to client: %v", err)
		}
		// Mark IP as in use so packets can be send to it. This is needed to avoid deadlock condition
		// when a client disconnects but still packets are available in buffer for its ip and a new
		// client acquires its ip it cannot get the config as the TUN writer is still busy trying to send
		// packets to it.
		if err := r.ipam.SetIPActiveWithUserInfo(ip, username, hostname); err != nil {
			return fmt.Errorf("Unable to mark IP %v in use", ip)
		}
	}
}

// processIncomingBinaryMessage process Binary packets coming from the websocket
// since it is assumed we are receiving IP packets we just send them directly
// to the tun interface for the OS to route those
func (r *WebTunnelServer) processIncomingBinaryMessage(message []byte) error {
	wc.PrintPacketIPv4(message, "Server <- Websocket")
	n, err := r.ifce.Write(message)
	if err != nil {
		return fmt.Errorf("error writing to tunnel %s", err)
	}

	r.updateMetricsForPacket(n)
}

// httpEndpoint defines the HTTP / Path. The "Sender" will send an initial request to this URL.
func (r *WebTunnelServer) httpEndpoint(w http.ResponseWriter, rcv *http.Request) {
	fmt.Fprint(w, "OK")
}

// healthEndpoint
func (r *WebTunnelServer) healthEndpoint(w http.ResponseWriter, rcv *http.Request) {
	m := r.GetMetrics()
	if m.Users < m.MaxUsers {
		fmt.Fprint(w, "OK")
	} else {
		http.Error(w, "Max Users Reached", 500)
	}
}

// metricEndpoint
func (r *WebTunnelServer) metricEndpoint(w http.ResponseWriter, rcv *http.Request) {
	fmt.Fprint(w, r.GetMetrics())
}

// GetMetrics returns the current server metrics.
func (r *WebTunnelServer) GetMetrics() *Metrics {
	r.metrics.Users = r.ipam.GetAllocatedCount() - 3 // 3 Ips are alllocated for net/gw/router
	return r.metrics
}

// DumpAllocations returns IP allocations information.
// This can be called using a custom Handler for debuging purpose
func (r *WebTunnelServer) DumpAllocations() map[string]*UserInfo {
	return r.ipam.DumpAllocations()
}

// updateMetric update the metrics on the server.
// Its is called for each packet going through an interface.
func (r *WebTunnelServer) updateMetricsForPacket(n int) {
	r.metricsLock.Lock()
	r.metrics.Bytes += n
	r.metrics.Packets++
	r.metricsLock.Unlock()
}

// ResetMetrics resets the metrics on the server.
func (r *WebTunnelServer) ResetMetrics() {
	r.metricsLock.Lock()
	r.metrics.Users = 0
	r.metrics.Packets = 0
	r.metrics.Bytes = 0
	r.metricsLock.Unlock()
}
