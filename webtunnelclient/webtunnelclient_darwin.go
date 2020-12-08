package webtunnelclient

import (
	"fmt"
	"os/exec"
)

// initializeTunnel assigns IP to tunnel and sets up routing via tunnel.
func SetIP(ipLocal, ipGW, ifceName string) error {
	cmd := exec.Command("/sbin/ifconfig", ifceName, "down")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting ip on tun %s", err)
	}
	cmd = exec.Command("/sbin/ifconfig", ifceName, ipLocal, ipGW, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting ip on tun %s", err)
	}
	return nil
}

func SetRoute(routePrefix, ifceName string) error {
	cmd := exec.Command("/sbin/route", "-n", "add", "-net", routePrefix, "-interface", ifceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting ip on tun %s", err)
	}
	return nil
}
