/*
Package webtunnelclient runs the client side of the webtunnel; websocket based VPN.
See examples for client implementation.
*/
package webtunnelclient

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/user"
	"sync"
	"time"

	wc "github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

// NewWaterInterface (Overridable) Return new water interface.
var NewWaterInterface = wc.NewWaterInterface

// IsConfigured (Overridable) Check if network interface configured.
var IsConfigured = wc.IsConfigured

// GetMacbyName (Overridable) Get HW address.
var GetMacbyName = wc.GetMacbyName

// Interface represents the network interface and its related configuration.
type Interface struct {
	IP           net.IP           // IP address.
	GWIP         net.IP           // Gateway IP.
	Netmask      net.IP           // Netmask of the interface.
	DNS          []net.IP         // IP of DNS servers.
	RoutePrefix  []*net.IPNet     // Route prefix to send via tunnel.
	LocalHWAddr  net.HardwareAddr // MAC address of network interface.
	GWHWAddr     net.HardwareAddr // fake MAC address of gateway.
	LeaseTime    uint32           // DHCP lease time.
	wc.Interface                  // Interface to network.
}

// WebtunnelClient represents the client struct.
type WebtunnelClient struct {
	Error          chan error                    // Channel to handle errors from goroutines.
	isWSReady      bool                          // true when Websocket is ready - used when reconnecting
	isNetReady     bool                          // true when network interface is ready.
	isStopped      bool                          // True when Stop() called.
	wsconn         *websocket.Conn               // Websocket connection.
	ifce           *Interface                    // Struct to hold interface configuration.
	userInitFunc   func(*Interface) error        // User supplied callback for OS initialization.
	wsWriteLock    sync.Mutex                    // Lock for Websocket Writes.
	wsReadLock     sync.Mutex                    // Lock for Websocket Reads.
	metricsLock    sync.Mutex                    // Lock for Metrics Writes.
	ifReadLock     sync.Mutex                    // Lock for Interface Reads.
	ifWriteLock    sync.Mutex                    // Lock for Interface Writes.
	packetCnt      int                           // Count of packets.
	bytesCnt       int                           // Count of bytes.
	serverIPPort   string                        // Websocket serverIP:Port.
	wsDialer       *websocket.Dialer             // websocket dialer with options.
	devType        water.DeviceType              // TUN/TAP.
	scheme         string                        // Websocket Scheme.
	leaseTime      uint32                        // DHCP lease time.
	session        string                        // Session Tracker from Server
	isTap          bool                          // Is the webclient using a TAP interface
	customTapParam *water.PlatformSpecificParams // Tap driver specific parameters
}

/*
NewWebtunnelClient returns an initialized webtunnel client

serverIPPort: IP:Port of the websocket server.

wsDialer: Initialized websocket dialer with options.

devType: Tun or Tap.

f: User callback function for any OS initialization (eg. manual routes etc) mostly used in TUN.

secure: Enable secure websocket connection

leaseTime: If TAP, the DHCP lease time in seconds.
*/
func NewWebtunnelClient(serverIPPort string, wsDialer *websocket.Dialer,
	isTap bool, f func(*Interface) error,
	secure bool, leaseTime uint32) (*WebtunnelClient, error) {

	scheme := "ws"
	if secure {
		scheme = "wss"
	}

	devType := water.DeviceType(water.TUN)
	if isTap {
		devType = water.DeviceType(water.TAP)
	}
	glog.V(2).Infof("DeviceType: %v", devType)

	return &WebtunnelClient{
		Error:        make(chan error),
		isNetReady:   false,
		isStopped:    false,
		isWSReady:    false,
		serverIPPort: serverIPPort,
		wsDialer:     wsDialer,
		devType:      devType,
		scheme:       scheme,
		leaseTime:    leaseTime,
		userInitFunc: f,
		isTap:        isTap,
	}, nil
}

// SetTapInterface sets the Tap ComponentId for Windows tap interface
// It will set it only if the value is different from tap0901 which is the default
func (w *WebtunnelClient) SetTapInterface(customTapParam *water.PlatformSpecificParams) {
	w.customTapParam = customTapParam
}

// PingHandler will return the function to handle the Ping sent from the server.
// It sends the time diff seen between the client and server.
func (w *WebtunnelClient) PingHandler(wsConn *websocket.Conn) func(appStr string) error {
	return func(aStr string) error {
		bt := []byte(aStr)
		val, _ := binary.Varint(bt)
		glog.V(1).Infof("ping received from server, time value: %v", val)
		buf := make([]byte, binary.MaxVarintLen64)
		tV := time.Now().UTC().UnixNano()
		binary.PutVarint(buf, tV-val) // we will send the servertime - our time
		if err := wsConn.WriteControl(websocket.PongMessage, buf, time.Now().Add(time.Duration(5*time.Second))); err != nil {
			glog.Warningf("pong failed: %v", err)
		}
		return nil
	}
}

// Start the client.
func (w *WebtunnelClient) Start() error {

	// Connect to websocket connection.
	u := url.URL{Scheme: w.scheme, Host: w.serverIPPort, Path: "/ws"}
	wsconn, _, err := w.wsDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	w.wsconn = wsconn
	w.isWSReady = true

	// Set alternate tap parameter if provided
	wtConfig := water.Config{
		DeviceType: w.devType,
	}
	if w.isTap && (w.customTapParam != nil) {
		wtConfig.PlatformSpecificParams = *w.customTapParam
	}

	// Start network interface.
	glog.V(2).Info("Initialize TAP network interface")
	handle, err := NewWaterInterface(wtConfig)
	if err != nil {
		return fmt.Errorf("error creating int %s", err)
	}
	w.ifce = &Interface{
		Interface: handle,
		LeaseTime: w.leaseTime,
	}

	// Configure network interface.
	glog.V(2).Info("Configure network interface")
	err = w.configureInterface()
	if err != nil {
		return err
	}

	// isStopped is set true in Stop(). Used to gracefully exit packet processors.
	w.isStopped = false

	// Set Ping Handler
	w.wsconn.SetPingHandler(w.PingHandler(w.wsconn))

	// Start packet processors.
	go w.processNetPacket()
	go w.processWSPacket()

	return nil
}

// SetServer changes the websocket connection end point.
func (w *WebtunnelClient) SetServer(serverIPPort string, secure bool, wsDialer *websocket.Dialer) {
	scheme := "ws"
	if secure {
		scheme = "wss"
	}
	w.serverIPPort = serverIPPort
	w.scheme = scheme
	w.wsDialer = wsDialer
}

// getUserInfo gets the username and hostname of the client
func (w *WebtunnelClient) getUserInfo() (string, error) {

	username, err := user.Current()
	if err != nil {
		return "", err
	}

	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	return username.Username + " " + hostname, nil

}

// configureInterface retrieves the client configuration from server and sends to Net daemon.
func (w *WebtunnelClient) configureInterface() error {
	// Get configuration from server.
	userinfo, err := w.getUserInfo()
	if err != nil {
		return err
	}

	if err := w.wsconn.WriteMessage(websocket.TextMessage, []byte("getConfig"+" "+userinfo)); err != nil {
		return err
	}
	cfg := &wc.ClientConfig{}
	if err := w.wsconn.ReadJSON(cfg); err != nil {
		return err
	}
	glog.V(1).Infof("Retrieved config from server %+v", *cfg)
	glog.V(1).Infof("Retrieved config from server %+v", *cfg.ServerInfo)

	var dnsIPs []net.IP
	for _, v := range cfg.DNS {
		dnsIPs = append(dnsIPs, net.ParseIP(v).To4())
	}
	var routes []*net.IPNet
	for _, v := range cfg.RoutePrefix {
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return err
		}
		routes = append(routes, n)
	}
	w.ifce.IP = net.ParseIP(cfg.IP).To4()
	w.ifce.GWIP = net.ParseIP(cfg.GWIp).To4()
	w.ifce.Netmask = net.ParseIP(cfg.Netmask).To4()
	w.ifce.DNS = dnsIPs
	w.ifce.RoutePrefix = routes
	w.ifce.GWHWAddr = wc.GenMACAddr()

	w.session = cfg.ServerInfo.Session

	// Call user supplied function for any OS initializations needed from cli.
	// Depending on OS this might be bringing up OS or other network commands.
	if err := w.userInitFunc(w.ifce); err != nil {
		return err
	}

	return nil
}

// Retry the connection after a disconnection
func (w *WebtunnelClient) Retry() error {
	userinfo, err := w.getUserInfo()
	if err != nil {
		return err
	}
	u := url.URL{Scheme: w.scheme, Host: w.serverIPPort, Path: "/ws"}
	wsconn, _, err := w.wsDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	w.wsconn = wsconn
	w.isWSReady = true

	configString := "getConfig" + " " + userinfo + " " + w.session
	if err := w.wsconn.WriteMessage(websocket.TextMessage, []byte(configString)); err != nil {
		return err
	}
	cfg := &wc.ClientConfig{}
	if err := w.wsconn.ReadJSON(cfg); err != nil {
		return err
	}
	glog.V(1).Infof("retrieved config from server %v", *cfg)
	// verify session config from server matches current config
	if cfg.ServerInfo.Session != w.session {
		return fmt.Errorf("reconnect mismatch on session, client wants: %v but server gives: %v",
			w.session,
			cfg.ServerInfo.Session,
		)
	}
	if !net.IP.Equal(net.ParseIP(cfg.IP).To4(), w.ifce.IP) {
		return fmt.Errorf("reconnect mismatch on IP, client wants: %v but server gives: %v",
			w.ifce.IP,
			net.ParseIP(cfg.IP).To4(),
		)
	}
	return nil
}

// Stop gracefully shutdowns the client after notifying the server.
func (w *WebtunnelClient) Stop() error {

	w.isNetReady = false
	w.isStopped = true

	// If stop is called without start return.
	if w.wsconn == nil || w.ifce == nil {
		return nil
	}
	// Read Writes in websocket do not support concurrency.
	w.wsWriteLock.Lock()
	err := w.wsconn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	w.wsWriteLock.Unlock()
	if err != nil {
		return err
	}
	// Wait for some time for server to terminate conn before closing on client end.
	// Otherwise its seen as a abnormal closure and will result in error.
	time.Sleep(time.Second)
	w.wsconn.Close()
	w.ifce.Close()
	return nil
}

func (w *WebtunnelClient) updateMetricsForPacket(n int) {
	w.metricsLock.Lock()
	w.packetCnt++
	w.bytesCnt += n
	w.metricsLock.Unlock()
}

// ResetMetrics reset the internal counters.
func (w *WebtunnelClient) ResetMetrics() {
	w.metricsLock.Lock()
	w.packetCnt = 0
	w.bytesCnt = 0
	w.metricsLock.Unlock()
}

// GetMetrics returns the internal metrics.
func (w *WebtunnelClient) GetMetrics() (int, int) {
	return w.packetCnt, w.bytesCnt
}

// IsInterfaceReady returns true when the network interface is ready and configured
// with the right IP address.
func (w *WebtunnelClient) IsInterfaceReady() bool {
	return w.isNetReady
}

// processWSPacket processes packets received from the Websocket connection and
// writes to the network interface.
func (w *WebtunnelClient) processWSPacket() {

	// Wait for tap/tun interface configuration to be complete by DHCP(TAP) or manual (TUN).
	// Otherwise writing to network interface will fail.
	for !IsConfigured(w.ifce.Name(), w.ifce.IP.String()) {
		time.Sleep(2 * time.Second)
		glog.V(1).Infof("Waiting for interface to be ready...")
	}
	// get the localHW addr only after network interface is configured.
	w.ifce.LocalHWAddr = GetMacbyName(w.ifce.Name())
	glog.V(1).Infof("Interface Ready.")
	w.isNetReady = true

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	for {
		// Skip if websocket is not ready - this means we are currently reconnecting
		if !w.isWSReady {
			continue
		}
		// Read packet from websocket.
		w.wsReadLock.Lock()
		mt, pkt, err := w.wsconn.ReadMessage()
		w.wsReadLock.Unlock()
		if err != nil {
			// Gracefully exit goroutine.
			if w.isStopped {
				return
			}
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				glog.Warning("Terminating after graceful closure from server")
				return
			}
			w.Error <- fmt.Errorf("error reading websocket %s", err)
			return
		}
		if mt != websocket.BinaryMessage {
			glog.Warningf("Binary message type recvd from websocket")
			continue
		}
		wc.PrintPacketIPv4(pkt, "Client <- WebSocket")

		// Wrap packet in Ethernet header before sending if TAP.
		if w.ifce.IsTAP() {
			packet := gopacket.NewPacket(pkt, layers.LayerTypeIPv4, gopacket.Default)
			ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

			ethl := &layers.Ethernet{
				SrcMAC:       w.ifce.GWHWAddr,
				DstMAC:       w.ifce.LocalHWAddr,
				EthernetType: layers.EthernetTypeIPv4,
			}
			buffer := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buffer, opts, ethl, ipv4, gopacket.Payload(ipv4.Payload)); err != nil {
				glog.Warningf("error serializelayer %s", err)
				continue
			}
			pkt = buffer.Bytes()
		}

		// Send packet to network interface.
		w.ifWriteLock.Lock()
		n, err := w.ifce.Write(pkt)
		w.ifWriteLock.Unlock()
		if err != nil {
			// Gracefully exit goroutine.
			if w.isStopped {
				return
			}
			w.Error <- fmt.Errorf("error writing to tunnel %s", err)
			return
		}
		w.updateMetricsForPacket(n)
	}
}

// processNetPacket processes the packet from the network interface and dispatches
// to the websocket connection.
func (w *WebtunnelClient) processNetPacket() {
	pkt := make([]byte, 2048)
	var oPkt []byte

	for {
		// Read from TUN/TAP network interface.
		w.ifReadLock.Lock()
		n, err := w.ifce.Read(pkt)
		w.ifReadLock.Unlock()
		if err != nil {
			// Gracefully exit goroutine.
			if w.isStopped {
				return
			}
			w.Error <- fmt.Errorf("error reading Tunnel %s. Sz:%v", err, n)
			return
		}
		oPkt = pkt[:n]

		w.updateMetricsForPacket(n)

		// Special handling for TAP; ARP/DHCP.
		if w.ifce.IsTAP() {
			packet := gopacket.NewPacket(oPkt, layers.LayerTypeEthernet, gopacket.Default)
			if _, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
				if err := w.handleArp(packet); err != nil {
					w.Error <- fmt.Errorf("err sending arp %v", err)
				}
				continue
			}
			if _, ok := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {
				if err := w.handleDHCP(packet); err != nil {
					w.Error <- fmt.Errorf("err sending dhcp  %v", err)
				}
				continue
			}
			// Only send IPv4 unicast packets to reduce noisy windows machines.
			ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok || ipv4.DstIP.IsMulticast() {
				wc.PrintPacketIPv4(oPkt, "Client  -> Websocket - droping non ipv4 packet")
				continue
			}
			// Strip Ethernet header and send.
			oPkt = packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet).LayerPayload()
		}

		wc.PrintPacketIPv4(oPkt, "Client  -> Websocket")
		w.wsWriteLock.Lock()
		err = w.wsconn.WriteMessage(websocket.BinaryMessage, oPkt)
		w.wsWriteLock.Unlock()
		if err != nil {
			// Gracefully exit goroutine.
			if w.isStopped {
				return
			}
			w.Error <- fmt.Errorf("error writing to websocket: %s", err)
			return
		}
	}
}

// buildDHCPopts builds the options for DHCP Response.
func (w *WebtunnelClient) buildDHCPopts(leaseTime uint32, msgType layers.DHCPMsgType) layers.DHCPOptions {
	var opt []layers.DHCPOption
	tm := make([]byte, 4)
	binary.BigEndian.PutUint32(tm, leaseTime)

	var dnsbytes []byte
	for _, s := range w.ifce.DNS {
		dnsbytes = append(dnsbytes, s...)
	}
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptDNS, dnsbytes))
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptSubnetMask, w.ifce.Netmask))
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptLeaseTime, tm))
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(msgType)}))
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptServerID, w.ifce.GWIP))

	// Construct the classless static route.
	// format: {size of netmask, <route prefix>, <gateway> ...}
	// The size of netmask dictates how to read the route prefix. (eg. 24 - read next 3 bytes or 25 read next 4 bytes)
	var route []byte
	for _, n := range w.ifce.RoutePrefix {
		netAddr := []byte(n.IP.To4())
		mask, _ := n.Mask.Size()
		b := mask / 8
		if mask%8 > 0 {
			b++
		}
		// Add only the size of netmask.
		netAddr = netAddr[:b]
		route = append(route, byte(mask))     // Add netmask size.
		route = append(route, netAddr...)     // Add network.
		route = append(route, w.ifce.GWIP...) // Add gateway.
	}
	opt = append(opt, layers.NewDHCPOption(layers.DHCPOptClasslessStaticRoute, route))

	return opt
}

// handleDHCP handles the DHCP requests from kernel.
func (w *WebtunnelClient) handleDHCP(packet gopacket.Packet) error {
	if w.isNetReady {
		glog.Info("Skipping DHCP response since IP is assigned")
		return nil
	}

	dhcp := packet.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	udp := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	ipv4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	// Get relevant info from DHCP request options.
	var msgType layers.DHCPMsgType
	var reqIP net.IP
	for _, v := range dhcp.Options {
		if v.Type == layers.DHCPOptMessageType {
			msgType = layers.DHCPMsgType(v.Data[0])
		}
		if v.Type == layers.DHCPOptRequestIP {
			reqIP = net.IP(v.Data)
		}

	}

	var dhcpl = &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  dhcp.HardwareLen,
		Xid:          dhcp.Xid,
		YourClientIP: w.ifce.IP,
		NextServerIP: w.ifce.GWIP,
		ClientHWAddr: eth.SrcMAC,
	}

	switch msgType {
	case layers.DHCPMsgTypeDiscover:
		dhcpl.Options = w.buildDHCPopts(w.ifce.LeaseTime, layers.DHCPMsgTypeOffer)

	case layers.DHCPMsgTypeRequest:
		// If the requested/client IP is not the same as from the config force a NAK
		// to start the discovery process again.
		if net.IP.Equal(reqIP, w.ifce.IP) || net.IP.Equal(dhcp.ClientIP, w.ifce.IP) {
			dhcpl.Options = w.buildDHCPopts(w.ifce.LeaseTime, layers.DHCPMsgTypeAck)
		} else {
			dhcpl.Options = w.buildDHCPopts(w.ifce.LeaseTime, layers.DHCPMsgTypeNak)
		}

	case layers.DHCPMsgTypeRelease:
		glog.Warningf("Got an IP release request. Unexpected.")
	}

	// Construct and send DHCP Packet.
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	ethl := &layers.Ethernet{
		SrcMAC:       w.ifce.GWHWAddr,
		DstMAC:       net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipv4l := &layers.IPv4{
		Version:  ipv4.Version,
		TTL:      ipv4.TTL,
		SrcIP:    w.ifce.GWIP,
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
	wc.PrintPacketEth(buffer.Bytes(), "DHCP Reply")
	w.ifWriteLock.Lock()
	_, err := w.ifce.Write(buffer.Bytes())
	w.ifWriteLock.Unlock()
	if err != nil {
		// Gracefully exit goroutine.
		if w.isStopped {
			return nil
		}
		return err
	}

	return nil
}

// handleArp handles the ARPs requests via the TAP interface. All responses are
// sent the virtual MAC HWAddr for gateway.
func (w *WebtunnelClient) handleArp(packet gopacket.Packet) error {

	arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	eth := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)

	if arp.Operation != layers.ARPRequest {
		return nil
	}

	arpl, ethl := w.extractArpDetails(arp, eth)

	// If the reply if for the VM TAP IP the source HW must be the TAP interface MAC addr
	// Otherwise some Os could detect IP conflicts
	if net.IP.Equal(net.IP(arpl.SourceProtAddress), w.ifce.IP) {
		if w.ifce.LocalHWAddr == nil {
			glog.V(2).Info("Interface is not yet ready - skip arp reply for the VM itself")
			return nil
		}
		arpl.SourceHwAddress = w.ifce.LocalHWAddr
		ethl.SrcMAC = w.ifce.LocalHWAddr
	}

	err := w.sendArpReply(arpl, ethl)
	if err != nil {
		// Gracefully exit goroutine.
		if w.isStopped {
			return nil
		}
		return err
	}
	return nil
}

func (w *WebtunnelClient) extractArpDetails(arp *layers.ARP, eth *layers.Ethernet) (*layers.ARP, *layers.Ethernet) {

	// Construct and send ARP response.
	arpl := layers.ARP{
		AddrType:          arp.AddrType,
		Protocol:          arp.Protocol,
		HwAddressSize:     arp.HwAddressSize,
		ProtAddressSize:   arp.ProtAddressSize,
		Operation:         layers.ARPReply,
		SourceHwAddress:   w.ifce.GWHWAddr,
		SourceProtAddress: arp.DstProtAddress,
		DstHwAddress:      arp.SourceHwAddress,
		DstProtAddress:    arp.SourceProtAddress,
	}
	ethl := layers.Ethernet{
		SrcMAC:       w.ifce.GWHWAddr,
		DstMAC:       eth.SrcMAC,
		EthernetType: layers.EthernetTypeARP,
	}
	return &arpl, &ethl
}

func (w *WebtunnelClient) sendArpReply(arpl *layers.ARP, ethl *layers.Ethernet) error {
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, opts, ethl, arpl); err != nil {
		return fmt.Errorf("error Serializelayer %s", err)
	}
	wc.PrintPacketEth(buffer.Bytes(), "ARP Response")
	w.ifWriteLock.Lock()
	_, err := w.ifce.Write(buffer.Bytes())
	w.ifWriteLock.Unlock()
	if err != nil {
		return err
	}
	return nil
}
