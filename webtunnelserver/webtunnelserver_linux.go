package webtunnelserver

import (
	"fmt"
	"os/exec"
)

func initializeTunnel(ifceName, tunIP, tunNetmask string) error {
	cmd := exec.Command("/sbin/ifconfig", ifceName, tunIP, "netmask", tunNetmask, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting ip on tun %s", err)
	}
	return nil
}
