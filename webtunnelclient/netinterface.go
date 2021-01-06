package webtunnelclient

import (
	"fmt"
	"net"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/songgao/water"
)

type NetIfce struct {
	handle       *water.Interface          // Handle to interface.
	RemoteAddr   *net.UDPAddr              // remote IP for client.
	InterfaceCfg *InterfaceCfg             // Interface Configuration.
	gwHWAddr     net.HardwareAddr          // Fake HW addr for Gateway IP. needed since we use TUN at server.
	initClient   func(*InterfaceCfg) error // Callback function for any OS initializations.
}

type InterfaceCfg struct {
	IP          string
	GWIP        string
	Netmask     string
	DNS         []string
	RoutePrefix []string
	IfceName    string
}

// NetNetIfce create a new tunnel interface.
func NewNetIfce(devType water.DeviceType, f func(*InterfaceCfg) error) (*NetIfce, error) {
	handle, err := water.New(water.Config{
		DeviceType: devType,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating int %s", err)
	}

	return &NetIfce{
		handle:     handle,
		gwHWAddr:   webtunnelcommon.GenMACAddr(),
		initClient: f,
	}, nil
}

// SetInterfaceCfg sets the interface configuration.
func (i *NetIfce) SetInterfaceCfg(a InterfaceCfg, r *struct{}) error {
	glog.V(1).Infof("Got net config from client cfg:%v, Ifce:%s", a, i.handle.Name())
	i.InterfaceCfg = &a
	i.InterfaceCfg.IfceName = i.handle.Name()

	// Call user supplied function for any OS initializations needed from cli.
	// Depending on OS this might be bringing up OS or other network commands.
	if err := i.initClient(i.InterfaceCfg); err != nil {
		return err
	}
	return nil
}

// SetRemote sets the remote UDP endpoint address of client.
func (i *NetIfce) SetRemote(addr *net.UDPAddr, r *struct{}) error {
	glog.V(1).Infof("New remote endpoint connected: %s", addr.String())
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
