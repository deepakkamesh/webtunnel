package webtunnelclient

import (
	"fmt"
	"net"
	"net/http"
	"net/rpc"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

type NetIfce struct {
	handle       *water.Interface // Handle to interface.
	RemoteAddr   *net.UDPAddr     // remote IP for client.
	InterfaceCfg *InterfaceCfg    // Interface Configuration.
	HardwareAddr net.HardwareAddr // Local Mac Address set if TAP only.
}

type InterfaceCfg struct {
	IP          string
	GWIP        string
	Netmask     string
	DNS         []string
	RoutePrefix []string
}

// NetNetIfce create a new tunnel interface.
func NewNetIfce(devType water.DeviceType) (*NetIfce, error) {
	handle, err := water.New(water.Config{
		DeviceType: devType,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating int %s", err)
	}
	// Get the mac address if its a TAP interface.
	var mac net.HardwareAddr
	if handle.IsTAP() {
		ints, err := net.Interfaces()
		if err != nil {
			return nil, err
		}
		for _, i := range ints {
			if i.Name == handle.Name() {
				mac = i.HardwareAddr
			}
		}
	}
	return &NetIfce{
		handle:       handle,
		HardwareAddr: mac,
	}, nil
}

func (i *NetIfce) SetInterfaceCfg(a InterfaceCfg, r *struct{}) error {
	glog.V(1).Infof("Got net config from client cfg:%v, Ifce:%s", a, i.handle.Name())
	i.InterfaceCfg = &a
	// If TAP, DHCP handles interface config. Nothing to do return.
	if i.handle.IsTAP() {
		return nil
	}
	// Tun devices need to be configured from cli.
	if i.handle.IsTUN() {
		if err := SetIP(&a, i.handle.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (i *NetIfce) SetRemote(addr *net.UDPAddr, r *struct{}) error {
	glog.Infof("New remote endpoint connected: %s", addr.String())
	i.RemoteAddr = addr
	return nil
}

func (i *NetIfce) Bye(s string, r *struct{}) error {
	return nil
}

// Ping function is called from Client to check health of Daemon.
func (i *NetIfce) Ping(s string, r *struct{}) error {
	return nil
}

// ClientDaemon represents a daemon structure.
type ClientDaemon struct {
	DaemonPort int          // Daemon IPPort.
	NetIfce    *NetIfce     // Handle to tunnel network interface.
	pktConn    *net.UDPConn // Handle to UDP connection.
	Error      chan error   // Channel to handle errors from goroutines.
}

// NewClientDaemon returns an initialized Client Daemon.
func NewClientDaemon(daemonPort int, devType water.DeviceType) (*ClientDaemon, error) {
	// Initialize Tunnel interface.
	netIfce, err := NewNetIfce(devType)
	if err != nil {
		return nil, err
	}
	glog.V(1).Infof("Created interface %s", netIfce.handle.Name())

	// Start UDP listener for packet messages.
	ser, err := net.ListenUDP("udp", &net.UDPAddr{Port: daemonPort, IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, err
	}

	return &ClientDaemon{
		DaemonPort: daemonPort,
		NetIfce:    netIfce,
		pktConn:    ser,
		Error:      make(chan error),
	}, nil
}

func (c *ClientDaemon) Start() error {

	// Register to RPC and start config Daemon.
	if err := rpc.Register(c.NetIfce); err != nil {
		return err
	}
	rpc.HandleHTTP()
	h, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", c.DaemonPort))
	if err != nil {
		return err
	}
	go http.Serve(h, nil)

	// Start the packet processors.
	if c.NetIfce.handle.IsTAP() {
		go c.processNetPktTAP()
		go c.processTAPPkt()
	}
	if c.NetIfce.handle.IsTUN() {
		go c.processNetPkt()
		go c.processTUNPkt()
	}

	return nil
}

func (c *ClientDaemon) Stop() error {
	if err := c.NetIfce.handle.Close(); err != nil {
		return err
	}
	return c.pktConn.Close()
}

func (c *ClientDaemon) processNetPkt() {
	pkt := make([]byte, 2048)

	for {
		if _, _, err := c.pktConn.ReadFrom(pkt); err != nil {
			c.Error <- fmt.Errorf("error reading udp %s.", err)
			return
		}
		webtunnelcommon.PrintPacketIPv4(pkt, "Daemon <- Client")
		if _, err := c.NetIfce.handle.Write(pkt); err != nil {
			c.Error <- fmt.Errorf("error writing to tunnel %s.", err)
			return
		}
	}
}

func (c *ClientDaemon) processTUNPkt() {
	pkt := make([]byte, 2048)
	// If Daemon is not configured do not process packets.
	for {
		if c.NetIfce.RemoteAddr == nil {
			continue
		}
		if _, err := c.NetIfce.handle.Read(pkt); err != nil {
			c.Error <- fmt.Errorf("error reading tunnel %s.", err)
			return
		}
		//TODO:remove	webtunnelcommon.PrintPacketIPv4(pkt, "Daemon -> Client")
		if _, err := c.pktConn.WriteTo(pkt, c.NetIfce.RemoteAddr); err != nil {
			c.Error <- fmt.Errorf("error writing to websocket: %s.", err)
			return
		}
	}
}
func (c *ClientDaemon) processNetPktTAP() {
	pkt := make([]byte, 2048)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	for {
		if _, _, err := c.pktConn.ReadFrom(pkt); err != nil {
			c.Error <- fmt.Errorf("error reading udp %s.", err)
			return
		}

		// Wrap packet in Ethernet header before sending.
		packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
		ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		ethl := &layers.Ethernet{
			SrcMAC:       c.NetIfce.HardwareAddr, // src/dst are same.
			DstMAC:       c.NetIfce.HardwareAddr,
			EthernetType: layers.EthernetTypeIPv4,
		}
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, opts, ethl, ipv4, gopacket.Payload(ipv4.Payload)); err != nil {
			glog.Errorf("error serializelayer %s", err)
		}

		webtunnelcommon.PrintPacketEth(buffer.Bytes(), "Daemon <- Client")
		if _, err := c.NetIfce.handle.Write(buffer.Bytes()); err != nil {
			c.Error <- fmt.Errorf("error writing to tunnel %s.", err)
			return
		}
	}
}

// processTAPPkt handles TAP interface.
func (c *ClientDaemon) processTAPPkt() {
	pkt := make([]byte, 2048)
	// If Daemon is not configured do not process packets.
	for {
		if c.NetIfce.RemoteAddr == nil {
			continue
		}
		if _, err := c.NetIfce.handle.Read(pkt); err != nil {
			c.Error <- fmt.Errorf("error reading tunnel %s.", err)
			return
		}

		// Intercept and handle Arp requests.
		packet := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
		_, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
		if ok {
			if err := c.handleArp(packet); err != nil {
				c.Error <- fmt.Errorf("err sending arp %v", err)
			}
			continue
		}

		// Send packet to client.
		//		webtunnelcommon.PrintPacketIPv4(eth.LayerPayload(), "Daemon -> Client")
		if _, err := c.pktConn.WriteTo(pkt, c.NetIfce.RemoteAddr); err != nil {
			c.Error <- fmt.Errorf("error writing to websocket: %s.", err)
			return
		}
	}
}

func (c *ClientDaemon) handleDHCP(ifce *water.Interface, packet gopacket.Packet) error {

	dhcp := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	// Get the DHCP Message Type.
	var msgType layers.DHCPMsgType
	for _, v := range dhcp.Options {
		if v.Type == layers.DHCPOptMessageType {
			msgType = layers.DHCPMsgType(v.Data[0])
		}
	}

	var dhcpl *layers.DHCPv4

	switch msgType {
	case layers.DHCPMsgTypeDiscover:

		dhcpl = &layers.DHCPv4{
			Operation:    0x2, // DHCP reply.
			HardwareType: layers.LinkTypeEthernet,
			HardwareLen:  dhcp.HardwareLen,
			HardwareOpts: 0,
			Xid:          dhcp.Xid,
			YourClientIP: net.IP{10, 10, 10, 10},
			NextServerIP: net.IP{192, 168, 251, 1},
			ClientHWAddr: eth.SrcMAC,
			Options: []layers.DHCPOption{
				layers.NewDHCPOption(layers.DHCPOptDNS, net.IP{192, 168, 251, 1}),
				layers.NewDHCPOption(layers.DHCPOptSubnetMask, net.IP{255, 255, 255, 0}),
				layers.NewDHCPOption(layers.DHCPOptLeaseTime, []byte{0, 0, 0, 10}),
				layers.NewDHCPOption(layers.DHCPOptServerID, net.IP{192, 168, 251, 1}),
				layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeOffer)}),
				layers.NewDHCPOption(layers.DHCPOptClasslessStaticRoute, []byte{25, 172, 57, 26, 10, 192, 168, 251, 1}),
			},
		}

	case layers.DHCPMsgTypeRequest:
		dhcpl = &layers.DHCPv4{
			Operation:    0x2, // DHCP reply.
			HardwareType: layers.LinkTypeEthernet,
			HardwareLen:  dhcp.HardwareLen,
			HardwareOpts: 0,
			Xid:          dhcp.Xid,
			YourClientIP: net.IP{10, 10, 10, 10},
			NextServerIP: net.IP{192, 168, 251, 1},
			ClientHWAddr: eth.SrcMAC,
			Options: []layers.DHCPOption{
				layers.NewDHCPOption(layers.DHCPOptDNS, net.IP{192, 168, 251, 1}),
				layers.NewDHCPOption(layers.DHCPOptSubnetMask, net.IP{255, 255, 255, 0}),
				layers.NewDHCPOption(layers.DHCPOptLeaseTime, []byte{0, 0, 0, 10}),
				layers.NewDHCPOption(layers.DHCPOptServerID, net.IP{192, 168, 251, 1}),
				layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeAck)}),
				layers.NewDHCPOption(layers.DHCPOptClasslessStaticRoute, []byte{25, 172, 57, 26, 10, 192, 168, 251, 1}),
			},
		}

	case layers.DHCPMsgTypeRelease:
		glog.Warningf("Got an IP release request. Unexpected.")
	}

	// Construct and send DHCP Packet.
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ethl := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x80, 0xE6, 0x50, 0x18, 0x9B, 0xBA},
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4l := &layers.IPv4{
		Version:  ipv4.Version,
		TTL:      ipv4.TTL,
		SrcIP:    net.IP{192, 168, 251, 1},
		DstIP:    net.IP{255, 255, 255, 255},
		Protocol: layers.IPProtocolUDP,
	}
	udpl := &layers.UDP{
		SrcPort: udp.DstPort,
		DstPort: udp.SrcPort,
	}
	if err := udpl.SetNetworkLayerForChecksum(ipv4l); err != nil {
		return fmt.Errorf("error checksum %s", err)
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, opts, ethl, ipv4l, udpl, dhcpl); err != nil {
		return fmt.Errorf("error Serializelayer %s", err)
	}
	fmt.Println(gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default))
	if _, err := c.NetIfce.handle.Write(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}

func (c *ClientDaemon) handleArp(packet gopacket.Packet) error {

	arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	if arp.Operation != layers.ARPRequest {
		return nil
	}

	// Create a fake mac to respond to ARP requests for gateway.
	vMac := eth.SrcMAC
	vMac[2] = +1

	// Construct and send ARP response.
	ethl := &layers.Ethernet{
		SrcMAC:       vMac,
		DstMAC:       eth.SrcMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	arpl := &layers.ARP{
		AddrType:          arp.AddrType,
		Protocol:          arp.Protocol,
		HwAddressSize:     arp.HwAddressSize,
		ProtAddressSize:   arp.ProtAddressSize,
		Operation:         layers.ARPReply,
		SourceHwAddress:   vMac,
		SourceProtAddress: arp.DstProtAddress,
		DstHwAddress:      arp.SourceHwAddress,
		DstProtAddress:    arp.SourceProtAddress,
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, opts, ethl, arpl); err != nil {
		return fmt.Errorf("error Serializelayer %s", err)
	}
	webtunnelcommon.PrintPacketEth(buffer.Bytes(), "ARP Response")
	if _, err := c.NetIfce.handle.Write(buffer.Bytes()); err != nil {
		return err
	}
	return nil
}
