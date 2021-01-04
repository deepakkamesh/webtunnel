package main

import (
	"fmt"
	"os/exec"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
)

// initializeTunnel assigns IP to tunnel and sets up routing via tunnel.
func InitializeOS(cfg *webtunnelclient.InterfaceCfg) error {
	cmd := exec.Command("/sbin/ifconfig", cfg.IfceName, "down")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting ip on tun %s", err)
	}
	cmd = exec.Command("/sbin/ifconfig", cfg.IfceName, cfg.IP, cfg.GWIP, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting ip on tun %s", err)
	}

	for _, route := range cfg.RoutePrefix {
		cmd := exec.Command("/sbin/route", "-n", "add", "-net", route, "-interface", cfg.IfceName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error setting route on tun %s", err)
		}
	}
	return nil
}
