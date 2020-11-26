package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

type Router struct {
	WSData   chan WSPkt                 // Channel to receive data from websocket.
	Conns    map[string]*websocket.Conn // Websocket connection.
	ethIface *pcap.Handle               // Handle for routeable network interface.
	tunIface *water.Interface           // Handle to the TUN interface.
}

func NewRouter(ethIfce string) (*Router, error) {

	// Open handle to routable network interface on host.
	handle, err := pcap.OpenLive(ethIfce, 1024, false, 30*time.Second)
	if err != nil {
		return nil, err
	}

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
	cmd := exec.Command("/sbin/ifconfig", tunIfce.Name(), "10.0.0.1", "netmask", "255.255.255.0", "up")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("error setting ip on tun %s", err)
	}
	return &Router{
		WSData:   make(chan WSPkt, 10),
		Conns:    make(map[string]*websocket.Conn),
		ethIface: handle,
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

			if err := sendNet(data.payload, r.ethIface); err != nil {
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

func sendNet(pkt []byte, handle *pcap.Handle) error {

	packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)

	ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// net.HardwareAddr{0x00,0x23,0x4d,0x09,0xfd,0x92} win
	//  net.HardwareAddr{0x80, 0xE6, 0x50, 0x18, 0x9B, 0xBA} Mac
	// net.HardwareAddr{0x18, 0x3D, 0xA2, 0x42, 0xE4, 0x4C}, lin
	ethl := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x18, 0x3D, 0xA2, 0x42, 0xE4, 0x4C},
		DstMAC:       net.HardwareAddr{0x00, 0x23, 0x4d, 0x09, 0xfd, 0x92},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ipl := &layers.IPv4{
		SrcIP:      ip.SrcIP, // net.IP{10, 2, 0, 1},// Source should change. TODO
		DstIP:      ip.DstIP,
		Protocol:   ip.Protocol,
		Version:    ip.Version,
		IHL:        ip.IHL,
		TOS:        ip.TOS,
		Id:         ip.Id,
		Flags:      ip.Flags,
		FragOffset: ip.FragOffset,
		TTL:        ip.TTL,
		Options:    ip.Options,
		Padding:    ip.Padding,
	}

	buffer := gopacket.NewSerializeBuffer()

	switch ip.NextLayerType() {
	case layers.LayerTypeUDP:
		trans := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if err := trans.SetNetworkLayerForChecksum(ipl); err != nil {
			return fmt.Errorf("error checksum %s", err)
		}
		if err := gopacket.SerializeLayers(buffer, opts, ethl, ipl, trans, gopacket.Payload(trans.Payload)); err != nil {
			return fmt.Errorf("error serializelayer %s", err)
		}

	case layers.LayerTypeTCP:
		trans := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if err := trans.SetNetworkLayerForChecksum(ipl); err != nil {
			return fmt.Errorf("error checksum %s", err)
		}

		trans.SetNetworkLayerForChecksum(ipl)
		if err := gopacket.SerializeLayers(buffer, opts, ethl, ipl, trans, gopacket.Payload(trans.Payload)); err != nil {
			return fmt.Errorf("error serializelayer %s", err)
		}

	case layers.LayerTypeICMPv4:
		trans := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if err := gopacket.SerializeLayers(buffer, opts, ethl, ipl, trans, gopacket.Payload(trans.Payload)); err != nil {
			return fmt.Errorf("error serializelayer %s", err)
		}
	}

	fmt.Println("send to Eth", gopacket.NewPacket(
		buffer.Bytes(),
		layers.LayerTypeEthernet,
		gopacket.Default,
	))

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		return fmt.Errorf("error send %s", err)
	}
	return nil
}
