package webtunnelserver

import (
	"fmt"
	"log"
	"net/http"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
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

type WebTunnelServer struct {
	serverIPPort     string                     // IP Port for binding on server.
	ifce             *water.Interface           // Tunnel interface handle.
	quitTUNProcessor chan struct{}              // Channel to get shutdown message.
	Conns            map[string]*websocket.Conn // Websocket connection.
	routePrefix      string                     // Route prefix for client config.
	clientNetPrefix  string                     // IP range for clients.
	gwIP             string                     // Tunnel IP address of server.
	ipam             *IPPam                     // Client IP Address manager.
	httpsKeyFile     string                     // Key file for HTTPS.
	httpsCertFile    string                     // Cert file for HTTPS.
}

func NewWebTunnelServer(serverIPPort, gwIP, tunNetmask, clientNetPrefix, routePrefix, httpsKeyFile, httpsCertFile string) (*WebTunnelServer, error) {

	// Create TUN interface and initialize it.
	ifce, err := water.New(
		water.Config{
			DeviceType: water.TUN,
		})
	if err != nil {
		return nil, fmt.Errorf("error creating TUN int %s", err)
	}
	if err := initializeTunnel(ifce.Name(), gwIP, tunNetmask); err != nil {
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
		serverIPPort:     serverIPPort,
		ifce:             ifce,
		quitTUNProcessor: make(chan struct{}),
		Conns:            make(map[string]*websocket.Conn),
		routePrefix:      routePrefix,
		clientNetPrefix:  clientNetPrefix,
		gwIP:             gwIP,
		ipam:             ipam,
		httpsKeyFile:     httpsKeyFile,
		httpsCertFile:    httpsCertFile,
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
	r.quitTUNProcessor <- struct{}{}
}

// processTUNPacket processes the packets read from tunnel.
func (r *WebTunnelServer) processTUNPacket() {

	pkt := make([]byte, 2048)
	for {
		if _, err := r.ifce.Read(pkt); err != nil {
			glog.Warningf("error reading from tunnel %s", err)
			continue
		}

		// Get dst IP and corresponding websocket connection.
		packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
		ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		data, err := r.ipam.GetData(ip.DstIP.String())
		if err != nil {
			glog.Warningf("unsolicited packet from IP:%v", ip.DstIP.String())
			continue
		}

		webtunnelcommon.PrintPacketIPv4(pkt, "Server <- Tunnel")

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
		glog.Errorf("error acquiring IP:%v", err)
		return
	}

	// Process websocket packet.
	for {
		mt, message, err := conn.ReadMessage()
		if err != nil {
			glog.Warningf("error reading from websocket for %s: %s ", rcv.RemoteAddr, err)
			return
		}
		webtunnelcommon.PrintPacketIPv4(message, "Server <- Websocket")

		switch mt {
		case websocket.TextMessage: // Control message.
			if string(message) == "getConfig" {
				cfg := &webtunnelcommon.ClientConfig{
					Ip:          ip,
					RoutePrefix: r.routePrefix,
					GWIp:        r.gwIP,
				}
				if err := conn.WriteJSON(cfg); err != nil {
					glog.Errorf("error sending config to client: %v", err)
					return
				}
			}

		case websocket.BinaryMessage: // Packet message.
			if err := sendNet(message, r.ifce); err != nil {
				glog.Warningf("error writing to tunnel %s", err)
				return
			}
		}
	}
}

// httpEndpoint defines the HTTP / Path. The "Sender" will send an initial request to this URL.
func (r *WebTunnelServer) httpEndpoint(w http.ResponseWriter, rcv *http.Request) {
	fmt.Fprint(w, "OK")
}

// sendNet sends packet on handle interface.
func sendNet(pkt []byte, handle *water.Interface) error {

	packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)

	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	buffer := gopacket.NewSerializeBuffer()

	switch ip.NextLayerType() {
	case layers.LayerTypeUDP:
		trans := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if err := trans.SetNetworkLayerForChecksum(ip); err != nil {
			return fmt.Errorf("error checksum %s", err)
		}
		if err := gopacket.SerializeLayers(buffer, opts, ip, trans, gopacket.Payload(trans.Payload)); err != nil {
			return fmt.Errorf("error serializelayer %s", err)
		}

	case layers.LayerTypeTCP:
		trans := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if err := trans.SetNetworkLayerForChecksum(ip); err != nil {
			return fmt.Errorf("error checksum %s", err)
		}

		trans.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buffer, opts, ip, trans, gopacket.Payload(trans.Payload)); err != nil {
			return fmt.Errorf("error serializelayer %s", err)
		}

	case layers.LayerTypeICMPv4:
		trans := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if err := gopacket.SerializeLayers(buffer, opts, ip, trans, gopacket.Payload(trans.Payload)); err != nil {
			return fmt.Errorf("error serializelayer %s", err)
		}
	}
	if _, err := handle.Write(buffer.Bytes()); err != nil {
		return fmt.Errorf("error sending to tun %s", err)
	}
	return nil
}
