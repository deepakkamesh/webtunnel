//go:build windows
// +build windows

// webtunclient_windows.go Windows specific OS initialization for client.
package main

import (
	"github.com/deepakkamesh/webtunnel/webtunnelclient"
)

// InitializeOS assigns IP to tunnel and sets up routing via tunnel.
func InitializeOS(cfg *webtunnelclient.Interface) error {
	return nil
}
