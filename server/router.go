package main

import (
	"fmt"
	"log"
	"os/exec"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

type Router struct {
	WSData   chan WSPkt                 // Channel to receive data from websocket.
	Conns    map[string]*websocket.Conn // Websocket connection.
	tunIface *water.Interface           // Handle to the TUN interface.
	quit     chan struct{}              // Channel to handle shutdown.
}

func NewRouter(tunIP, tunNetmask string) (*Router, error) {

	// Create TUN interface.
	tunIfce, err := water.New(
		water.Config{
			DeviceType: water.TUN,
		})
	if err != nil {
		return nil, fmt.Errorf("error creating TUN int %s", err)
	}

	// Assign IP to TUN.
	// TODO: Handle other Operating Systems and add routing for network prefixs.
	cmd := exec.Command("/sbin/ifconfig", tunIfce.Name(), tunIP, "netmask", tunNetmask, "up")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error setting ip on tun %s", err)
	}
	return &Router{
		WSData:   make(chan WSPkt, 10),
		Conns:    make(map[string]*websocket.Conn),
		tunIface: tunIfce,
	}, nil
}

func (r *Router) Start() {

	// Read and process packets from websocket.
	go func() {
		for {
			data := <-r.WSData

			fmt.Println("recv from WS", gopacket.NewPacket(
				data.payload,
				layers.LayerTypeIPv4,
				gopacket.Default,
			))

			if err := sendNet(data.payload, r.tunIface); err != nil {
				log.Fatalf("Error processing packet from WS %s", err)
			}
		}
	}()

	// Read and process packets from the tunnel interface.
	go func() {
		packet := make([]byte, 2000)
		for {
			if _, err := r.tunIface.Read(packet); err != nil {
				log.Fatalf("Error reading from Tunnel %s", err)
			}
			fmt.Println("recv from TUN ", gopacket.NewPacket(
				packet,
				layers.LayerTypeIPv4,
				gopacket.Default,
			))
			if err := sendWS(packet, r.Conns["10.0.0.2"]); err != nil {
				log.Printf("error sending to websocket %s", err)
			}
		}
	}()
}

// NewConn adds the websock into a map associating with an IP.
func (r *Router) NewConn(conn *websocket.Conn) {
	ip := r.getFreeIP()
	r.Conns[ip] = conn
}

func (r *Router) CloseConn(conn *websocket.Conn) {
}

func (r *Router) getFreeIP() string {
	return "10.0.0.2"
}

func (r *Router) getIPforConn(*websocket.Conn) string {
	return "10.0.0.2"
}

func sendWS(pkt []byte, conn *websocket.Conn) error {
	if conn == nil {
		return fmt.Errorf("invalid WebSocket")
	}
	if err := conn.WriteMessage(websocket.BinaryMessage, pkt); err != nil {
		return err
	}
	return nil
}

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

	fmt.Println("send to Tun", gopacket.NewPacket(
		buffer.Bytes(),
		layers.LayerTypeEthernet,
		gopacket.Default,
	))

	if _, err := handle.Write(buffer.Bytes()); err != nil {
		return fmt.Errorf("error sending to tun %s", err)
	}
	return nil
}
