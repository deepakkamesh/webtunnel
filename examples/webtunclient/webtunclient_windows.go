//go:build windows
// +build windows

// webtunclient_windows.go Windows specific OS initialization for client.
package main

import (
	"flag"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
	"github.com/golang/glog"
	"github.com/songgao/water"
)

var tunName = flag.String("tunName", "tun0901", "TUN iface name for OpenVPN version")

// InitializeOS assigns IP to tunnel and sets up routing via tunnel.
func InitializeOS(cfg *webtunnelclient.Interface) error {
	return nil
}

func clientPlatformSpecifics(client *webtunnelclient.WebtunnelClient) {
	if *tunName != "tap0901" {
		glog.V(1).Info("Overriding Tap Interface")
		customTapParams := &water.PlatformSpecificParams{
			ComponentID: *tunName,
			Network:     "192.168.1.10/24",
		}
		client.SetTapInterface(customTapParams)
	}
}
