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

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

type Metrics struct {
	Users   int // Total connected users.
	Packets int // total packets.
	Bytes   int // bytes pushed.
}

type WebTunnelServer struct {
	serverIPPort    string                     // IP Port for binding on server.
	ifce            wc.Interface               // Tunnel interface handle.
	Conns           map[string]*websocket.Conn // Websocket connection.
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

}

// To override in testing.
var initTunnel = initializeTunnel
var NewWaterInterface = func(c water.Config) (wc.Interface, error) {
	return water.New(c)
}

func NewWebTunnelServer(serverIPPort, gwIP, tunNetmask, clientNetPrefix string, dnsIPs []string, routePrefix []string, httpsKeyFile string, httpsCertFile string) (*WebTunnelServer, error) {

	// Create TUN interface and initialize it.
	ifce, err := NewWaterInterface(water.Config{
		DeviceType: water.TUN,
	})

	if err != nil {
		return nil, fmt.Errorf("error creating TUN int %s", err)
	}
	if err := initTunnel(ifce.Name(), gwIP, tunNetmask); err != nil {
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
		Conns:           make(map[string]*websocket.Conn),
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
	}, nil
}

func (r *WebTunnelServer) Start() {

	// Start the HTTP Server.
	http.HandleFunc("/", r.httpEndpoint)
	http.HandleFunc("/ws", r.wsEndpoint)
	go func() { log.Fatal(http.ListenAndServeTLS(r.serverIPPort, r.httpsCertFile, r.httpsKeyFile, nil)) }()

	// Read and process packets from the tunnel interface.
	go r.processTUNPacket()
}

func (r *WebTunnelServer) Stop() {
}

// processTUNPacket processes the packets read from tunnel.
func (r *WebTunnelServer) processTUNPacket() {
	defer func() { r.Error <- nil }()
	pkt := make([]byte, 2048)

	for {
		n, err := r.ifce.Read(pkt)
		if err != nil {
			r.Error <- fmt.Errorf("error reading from tunnel %s", err)
			return
		}

		// Add to metrics.
		r.metrics.Bytes += n
		r.metrics.Packets++

		// Get dst IP and corresponding websocket connection.
		packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
		ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		data, err := r.ipam.GetData(ip.DstIP.String())
		if err != nil {
			glog.V(2).Infof("unsolicited packet for IP:%v", ip.DstIP.String())
			continue
		}

		wc.PrintPacketIPv4(pkt, "Server <- Tunnel")

		ws := data.(*websocket.Conn)
		if err := ws.WriteMessage(websocket.BinaryMessage, pkt); err != nil {
			glog.Warningf("error writing to websocket %s", err)
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
				return
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
