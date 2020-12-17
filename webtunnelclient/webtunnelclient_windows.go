package webtunnelclient

// initializeTunnel assigns IP to tunnel and sets up routing via tunnel.
func SetIP(ipLocal, ipGW, ifceName string) error {
	/*	cmd = exec.Command("netsh",
			fmt.Sprintf("interface ip set address name=\"%s\" source=static addr=%s gateway=%s", ifceName, ipLocal, ipGW))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error setting ip on tun %s", err)
		}*/
	return nil
}

func SetRoute(routePrefix, ifceName string) error {
	/*	_, m, err := net.ParseCIDR(routePrefix)
		if err != nil {
			return err
		}
		netmask := fmt.Sprintf("%d.%d.%d.%d", m.Mask[0], m.Mask[1], m.Mask[2], m.Mask[3])
		cmd := exec.Command("route", "add", routePrefix, "netmask", netmask, ifceName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("error setting ip on tun %s", err)
		}*/
	return nil
}
