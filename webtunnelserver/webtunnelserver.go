package webtunnelserver

import (
	"fmt"
	"log"
	"net/http"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
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
	DiagLevel        int                        // Enable packet dumps.
	Diag             chan string                // Packet dump string.
	Error            chan error                 // Channel to handle error from packet processors.
	quitTUNProcessor chan struct{}              // Channel to get shutdown message.
	Conns            map[string]*websocket.Conn // Websocket connection.
	routePrefix      string                     // Route prefix for client config.
	clientNetPrefix  string                     // IP range for clients.
	gwIP             string                     // Tunnel IP address of server.
}

func NewWebTunnelServer(DiagLevel int, serverIPPort, gwIP, tunNetmask, routePrefix, clientNetPrefix string) (*WebTunnelServer, error) {

	// Create TUN interface.
	ifce, err := water.New(
		water.Config{
			DeviceType: water.TUN,
		})
	if err != nil {
		return nil, fmt.Errorf("error creating TUN int %s", err)
	}
	// Assign IP to TUN.
	if err := initializeTunnel(ifce.Name(), gwIP, tunNetmask); err != nil {
		return nil, err
	}
	return &WebTunnelServer{
		serverIPPort:     serverIPPort,
		ifce:             ifce,
		DiagLevel:        DiagLevel,
		Diag:             make(chan string),
		Error:            make(chan error),
		quitTUNProcessor: make(chan struct{}),
		Conns:            make(map[string]*websocket.Conn),
		routePrefix:      routePrefix,
		clientNetPrefix:  clientNetPrefix,
		gwIP:             gwIP,
	}, nil
}

func (r *WebTunnelServer) Start() {

	// Start the HTTP Server.
	http.HandleFunc("/", r.httpEndpoint)
	http.HandleFunc("/ws", r.wsEndpoint)
	go func() { log.Fatal(http.ListenAndServe(r.serverIPPort, nil)) }()

	// Read and process packets from the tunnel interface.
	go r.processTUNPacket()
}

func (r *WebTunnelServer) Stop() {
	r.quitTUNProcessor <- struct{}{}
}

func (r *WebTunnelServer) processTUNPacket() {

	pkt := make([]byte, 2000)
	for {
		select {
		case <-r.quitTUNProcessor:
			return

		default:
			if _, err := r.ifce.Read(pkt); err != nil {
				r.Error <- fmt.Errorf("error reading from tunnel %s", err)
			}
			//TODO: fixme
			ws := r.Conns["10.0.0.2"]
			if ws == nil {
				continue
			}
			if err := ws.WriteMessage(websocket.BinaryMessage, pkt); err != nil {
				r.Error <- fmt.Errorf("error writing to websocket %s", err)
			}
			if r.DiagLevel >= webtunnelcommon.DiagLevelDebug {
				r.Diag <- fmt.Sprintln("recv from TUN ", gopacket.NewPacket(
					pkt,
					layers.LayerTypeIPv4,
					gopacket.Default,
				))
			}
		}
	}
}

// wsEndpoint defines HTTP Websocket Path and upgrades the HTTP connection.
func (r *WebTunnelServer) wsEndpoint(w http.ResponseWriter, rcv *http.Request) {

	// Upgrade HTTP connection to a WebSocket connection.
	conn, err := upgrader.Upgrade(w, rcv, nil)
	if err != nil {
		log.Printf("Error upgrading to websocket: %s\n", err)
		return
	}
	defer conn.Close()

	// Add connection to Router. // TODO fix.
	r.Conns["10.0.0.2"] = conn

	for {
		mt, message, err := conn.ReadMessage()
		if err != nil {
			r.Error <- fmt.Errorf("error reading from websocket for %s: %s ", rcv.RemoteAddr, err)
			return
		}

		switch mt {
		case websocket.TextMessage: // Control message.
			if string(message) == "getConfig" {
				cfg := &webtunnelcommon.ClientConfig{
					Ip:          "10.0.0.2",
					RoutePrefix: r.routePrefix,
					GWIp:        r.gwIP,
				}
				fmt.Println(cfg)
				if err := conn.WriteJSON(cfg); err != nil {
					return
				}
			}

		case websocket.BinaryMessage: // Packet message.
			if err := sendNet(message, r.ifce); err != nil {
				r.Error <- fmt.Errorf("error writing to tunnel %s", err)
				return
			}
			if r.DiagLevel >= webtunnelcommon.DiagLevelDebug {
				r.Diag <- fmt.Sprintln("recv from WS", gopacket.NewPacket(
					message,
					layers.LayerTypeIPv4,
					gopacket.Default,
				))
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

	/*
		fmt.Println("send to Tun", gopacket.NewPacket(
			buffer.Bytes(),
			layers.LayerTypeIPv4,
			gopacket.Default,
		)) */

	if _, err := handle.Write(buffer.Bytes()); err != nil {
		return fmt.Errorf("error sending to tun %s", err)
	}
	return nil
}
