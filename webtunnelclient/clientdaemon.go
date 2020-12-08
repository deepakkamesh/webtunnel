package webtunnelclient

import (
	"fmt"
	"net"
	"net/http"
	"net/rpc"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

type NetIfce struct {
	IP          string           // Interface Ip.
	GWIP        string           // Tunnel endpoint.
	RoutePrefix string           // Route through device.
	handle      *water.Interface // Handle to interface.
	RemoteAddr  *net.UDPAddr     // remote IP for client.
}
type Addr struct {
}

type SetIPArgs struct {
	IP   string
	GWIP string
}

// NetNetIfce create a new tunnel interface.
func NewNetIfce() (*NetIfce, error) {
	// Create TUN interface.
	handle, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating TUN int %s", err)
	}
	return &NetIfce{
		handle: handle,
	}, nil
}

func (i *NetIfce) SetIP(a SetIPArgs, r *struct{}) error {
	return SetIP(a.IP, a.GWIP, i.handle.Name())
}

func (i *NetIfce) SetRoute(routePrefix string, r *struct{}) error {
	return SetRoute(routePrefix, i.handle.Name())
}

func (i *NetIfce) SetRemote(addr *net.UDPAddr, r *struct{}) error {
	i.RemoteAddr = addr
	return nil
}

// ClientDaemon represents a daemon structure.
type ClientDaemon struct {
	DaemonPort int
	NetIfce    *NetIfce
	pktConn    *net.UDPConn
	Error      chan error
	Diag       chan string
	DiagLevel  int
}

// NewClientDaemon returns an initialized Client Daemon.
func NewClientDaemon(daemonPort int, diagLevel int) (*ClientDaemon, error) {
	// Initialize Tunnel interface.
	netIfce, err := NewNetIfce()
	if err != nil {
		return nil, err
	}

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
		Diag:       make(chan string),
		DiagLevel:  diagLevel,
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

	// Start the packet processor.
	go c.processNetPkt()
	go c.processTUNPkt()
	return nil
}

func (c *ClientDaemon) processNetPkt() {
	pkt := make([]byte, 2048)
	var err error
	for {
		if _, _, err = c.pktConn.ReadFrom(pkt); err != nil {
			c.Error <- fmt.Errorf("error reading udp %s", err)
		}
		if _, err := c.NetIfce.handle.Write(pkt); err != nil {
			c.Error <- fmt.Errorf("error writing to tunnel %s", err)
		}
		if c.DiagLevel >= webtunnelcommon.DiagLevelDebug {
			c.Diag <- fmt.Sprintln("Daemon recv from Client", gopacket.NewPacket(
				pkt,
				layers.LayerTypeIPv4,
				gopacket.Default,
			))
		}
	}
}

func (c *ClientDaemon) processTUNPkt() {
	pkt := make([]byte, 2048)
	for {
		if _, err := c.NetIfce.handle.Read(pkt); err != nil {
			c.Error <- fmt.Errorf("error reading tunnel %s", err)
		}
		if _, err := c.pktConn.WriteTo(pkt, c.NetIfce.RemoteAddr); err != nil {
			c.Error <- fmt.Errorf("error writing to websocket: %s", err)
		}
		if c.DiagLevel >= webtunnelcommon.DiagLevelDebug {
			c.Diag <- fmt.Sprintln("Daemon recv from TUN", gopacket.NewPacket(
				pkt,
				layers.LayerTypeIPv4,
				gopacket.Default,
			))
		}
	}
}
