// webtunclient_darwin.go Darwin specific OS initialization for client.
package main

import (
	"fmt"
	"os/exec"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
)

// InitializeOS assigns IP to tunnel and sets up routing via tunnel.
func InitializeOS(cfg *webtunnelclient.Interface) error {

	cmd := exec.Command("/sbin/ifconfig", cfg.Name(), "down")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error downing tun %s %s", err, out)
	}

	cmd = exec.Command("/sbin/ifconfig", cfg.Name(), cfg.IP.String(), cfg.GWIP.String(), "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("error setting ip on tun %s %s", err, out)
	}

	for _, route := range cfg.RoutePrefix {
		cmd := exec.Command("/sbin/route", "-n", "add", "-net", route.String(), "-interface", cfg.Name())
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("error setting route on tun %s %s", err, out)
		}
	}
	return nil
}
