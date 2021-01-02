package webtunnelclient

import (
	"fmt"
	"net"

	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
	"github.com/songgao/water"
)

type NetIfce struct {
	handle       *water.Interface // Handle to interface.
	RemoteAddr   *net.UDPAddr     // remote IP for client.
	InterfaceCfg *InterfaceCfg    // Interface Configuration.
	localHWAddr  net.HardwareAddr // Local Mac Address set if TAP only.
	gwHWAddr     net.HardwareAddr // Fake HW addr for Gateway IP. needed since we use TUN at server.
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

	return &NetIfce{
		handle:      handle,
		localHWAddr: webtunnelcommon.GetMacbyName(handle.Name()),
		gwHWAddr:    webtunnelcommon.GenMACAddr(),
	}, nil
}

// SetInterfaceCfg sets the interface configuration.
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

// SetRemote sets the remote UDP endpoint address of client.
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
