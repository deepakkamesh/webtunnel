package webtunnelclient

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"time"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

// ClientDaemon represents a daemon structure.
type ClientDaemon struct {
	DaemonPort int          // Daemon IPPort.
	NetIfce    *NetIfce     // Handle to tunnel network interface.
	pktConn    *net.UDPConn // Handle to UDP connection.
	Error      chan error   // Channel to handle errors from goroutines.
	leaseTime  uint32       // DHCP lease time.
}

// NewClientDaemon returns an initialized Client Daemon.
func NewClientDaemon(daemonPort int, devType water.DeviceType, f func(*InterfaceCfg) error) (*ClientDaemon, error) {
	// Initialize network interface.
	netIfce, err := NewNetIfce(devType, f)
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
		leaseTime:  300, // leasetime 5min.
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
	go c.processNetPkt()
	go c.processTUNTAPPkt()

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
	var oPkt []byte
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Wait for tap/tun interface configuration to be complete by DHCP(TAP) or manual (TUN).
	// Otherwise writing to network interface will fail.
	for c.NetIfce.InterfaceCfg == nil || !webtunnelcommon.IsConfigured(c.NetIfce.handle.Name(), c.NetIfce.InterfaceCfg.IP) {
		time.Sleep(50 * time.Millisecond)
	}
	// Get TAP HW Addr since its now configured.
	localHWAddr := webtunnelcommon.GetMacbyName(c.NetIfce.handle.Name())

	for {
		// Read from UDP (client).
		n, _, err := c.pktConn.ReadFrom(pkt)
		if err != nil {
			c.Error <- fmt.Errorf("error reading Udp %s. Size:%v", err, n)
			return
		}
		oPkt = pkt
		webtunnelcommon.PrintPacketIPv4(oPkt, "Daemon <- Client")

		// Wrap packet in Ethernet header before sending if TAP.
		if c.NetIfce.handle.IsTAP() {
			packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
			ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

			ethl := &layers.Ethernet{
				SrcMAC:       c.NetIfce.gwHWAddr,
				DstMAC:       localHWAddr,
				EthernetType: layers.EthernetTypeIPv4,
			}
			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buffer, opts, ethl, ipv4, gopacket.Payload(ipv4.Payload)); err != nil {
				glog.Errorf("error serializelayer %s", err)
			}
			oPkt = buffer.Bytes()
		}

		// Send packet to network interface.
		if _, err := c.NetIfce.handle.Write(oPkt); err != nil {
			c.Error <- fmt.Errorf("error writing to tunnel %s.", err)
			return
		}
	}
}

func (c *ClientDaemon) processTUNTAPPkt() {
	pkt := make([]byte, 2048)
	var oPkt []byte

	// Wait for Daemon to be configured or writes to client will fail.
	for c.NetIfce.RemoteAddr == nil || c.NetIfce.InterfaceCfg == nil {
		time.Sleep(100 * time.Millisecond)
		continue
	}

	for {
		// Read from TUN/TAP network interface.
		n, err := c.NetIfce.handle.Read(pkt)
		if err != nil {
			c.Error <- fmt.Errorf("error reading Tunnel %s. Sz:%v", err, n)
			return
		}
		oPkt = pkt

		// Special handling for TAP; ARP/DHCP.
		if c.NetIfce.handle.IsTAP() {
			packet := gopacket.NewPacket(pkt, layers.LayerTypeEthernet, gopacket.Default)
			if _, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
				if err := c.handleArp(packet); err != nil {
					c.Error <- fmt.Errorf("err sending arp %v", err)
				}
				continue
			}
			if _, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {
				if err := c.handleDHCP(packet); err != nil {
					c.Error <- fmt.Errorf("err sending dhcp  %v", err)
				}
				continue
			}
			// Only send IPv4 unicast packets to reduce noisy windows machines.
			ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || ipv4.DstIP.IsMulticast() {
				continue
			}
			// Strip Ethernet header and send.
			oPkt = packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).LayerPayload()
		}

		// Send packet to client via UDP.
		webtunnelcommon.PrintPacketIPv4(oPkt, "Daemon -> Client")
		if _, err := c.pktConn.WriteTo(oPkt, c.NetIfce.RemoteAddr); err != nil {
			c.Error <- fmt.Errorf("error writing to websocket: %s.", err)
			return
		}
	}
}

func (c *ClientDaemon) buildDHCPopts(leaseTime uint32, msgType layers.DHCPMsgType) layers.DHCPOptions {
	var opt []layers.DHCPOption
	tm := make([]byte, 4)
	binary.BigEndian.PutUint32(tm, leaseTime)

	for _, s := range c.NetIfce.InterfaceCfg.DNS {
		opt = append(opt, layers.NewDHCPOption(layers.DHCPOptDNS, net.ParseIP(s).To4()))
	}
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptSubnetMask, net.ParseIP(c.NetIfce.InterfaceCfg.Netmask).To4()))
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptLeaseTime, tm))
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)}))
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptServerID, net.ParseIP(c.NetIfce.InterfaceCfg.GWIP).To4()))

	// Construct the classless static route.
	// format: {size of netmask, <route prefix>, <gateway> ...}
	// The size of netmask dictates how to read the route prefix. (eg. 24 - read next 3 bytes or 25 read next 4 bytes)
	var route []byte
	for _, r := range c.NetIfce.InterfaceCfg.RoutePrefix {
		_, n, _ := net.ParseCIDR(r)
		netAddr := []byte(n.IP.To4())
		mask, _ := n.Mask.Size()
		b := mask / 8
		if mask%8 > 0 {
			b++
		}
		// Add only the size of netmask.
		netAddr = netAddr[:b]
		route = append(route, byte(mask))                                        // Add netmask size.
		route = append(route, netAddr...)                                        // Add network.
		route = append(route, net.ParseIP(c.NetIfce.InterfaceCfg.GWIP).To4()...) // Add gateway.
	}
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptClasslessStaticRoute, route))

	return opt
}

func (c *ClientDaemon) handleDHCP(packet gopacket.Packet) error {

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

	var dhcpl = &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  dhcp.HardwareLen,
		Xid:          dhcp.Xid,
		YourClientIP: net.ParseIP(c.NetIfce.InterfaceCfg.IP).To4(),
		NextServerIP: net.ParseIP(c.NetIfce.InterfaceCfg.GWIP).To4(),
		ClientHWAddr: eth.SrcMAC,
	}

	switch msgType {
	case layers.DHCPMsgTypeDiscover:
		dhcpl.Options = c.buildDHCPopts(c.leaseTime, layers.DHCPMsgTypeOffer)

	case layers.DHCPMsgTypeRequest:
		dhcpl.Options = c.buildDHCPopts(c.leaseTime, layers.DHCPMsgTypeAck)

	case layers.DHCPMsgTypeRelease:
		glog.Warningf("Got an IP release request. Unexpected.")
	}

	// Construct and send DHCP Packet.
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ethl := &layers.Ethernet{
		SrcMAC:       c.NetIfce.gwHWAddr,
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4l := &layers.IPv4{
		Version:  ipv4.Version,
		TTL:      ipv4.TTL,
		SrcIP:    net.ParseIP(c.NetIfce.InterfaceCfg.GWIP).To4(),
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
		return fmt.Errorf("error serializelayer %s", err)
	}
	webtunnelcommon.PrintPacketEth(buffer.Bytes(), "DHCP Reply")
	if _, err := c.NetIfce.handle.Write(buffer.Bytes()); err != nil {
		return err
	}

	return nil
}

// handleArp handles the ARPs requests via the TAP interface. All responses are
// sent the virtual MAC HWAddr for gateway.
func (c *ClientDaemon) handleArp(packet gopacket.Packet) error {

	arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	if arp.Operation != layers.ARPRequest {
		return nil
	}

	// Construct and send ARP response.
	arpl := &layers.ARP{
		AddrType:          arp.AddrType,
		Protocol:          arp.Protocol,
		HwAddressSize:     arp.HwAddressSize,
		ProtAddressSize:   arp.ProtAddressSize,
		Operation:         layers.ARPReply,
		SourceHwAddress:   c.NetIfce.gwHWAddr,
		SourceProtAddress: arp.DstProtAddress,
		DstHwAddress:      arp.SourceHwAddress,
		DstProtAddress:    arp.SourceProtAddress,
	}
	ethl := &layers.Ethernet{
		SrcMAC:       c.NetIfce.gwHWAddr,
		DstMAC:       eth.SrcMAC,
		EthernetType: layers.EthernetTypeARP,
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
