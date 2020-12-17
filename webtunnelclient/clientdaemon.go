package webtunnelclient

import (
	"fmt"
	"net"
	"net/http"
	"net/rpc"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/songgao/water"
)

type NetIfce struct {
	handle     *water.Interface // Handle to interface.
	RemoteAddr *net.UDPAddr     // remote IP for client.
}

type SetIPArgs struct {
	IP   string
	GWIP string
}

// NetNetIfce create a new tunnel interface.
func NewNetIfce() (*NetIfce, error) {
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
	glog.V(1).Infof("Got net config from client IP:%s, GW:%s, Ifce:%s", a.IP, a.GWIP, i.handle.Name())
	return SetIP(a.IP, a.GWIP, i.handle.Name())
}

func (i *NetIfce) SetRoute(routePrefix string, r *struct{}) error {
	glog.V(1).Infof("Got route info from client:%s", routePrefix)
	return SetRoute(routePrefix, i.handle.Name())
}

func (i *NetIfce) SetRemote(addr *net.UDPAddr, r *struct{}) error {
	glog.Infof("New remote endpoint connected: %s", addr.String())
	i.RemoteAddr = addr
	return nil
}

func (i *NetIfce) SetDNS(dnsServer string, r *struct{}) error {
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

	for {
		if _, err := c.NetIfce.handle.Read(pkt); err != nil {
			c.Error <- fmt.Errorf("error reading tunnel %s.", err)
			return
		}
		webtunnelcommon.PrintPacketIPv4(pkt, "Daemon -> Client")
		if _, err := c.pktConn.WriteTo(pkt, c.NetIfce.RemoteAddr); err != nil {
			c.Error <- fmt.Errorf("error writing to websocket: %s.", err)
			return
		}
	}
}
