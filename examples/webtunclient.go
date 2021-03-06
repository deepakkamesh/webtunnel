// webtunclient.go - Example client implementation.
package main

import (
	"crypto/tls"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
	"github.com/golang/glog"
	"github.com/gorilla/websocket"
)

func main() {
	flag.Parse()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Initialize and Startup Webtunnel.
	glog.Warning("Starting WebTunnel...")

	// Create a dialer with options.
	wsDialer := websocket.Dialer{}
	wsDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// Initialize the client.
	client, err := webtunnelclient.NewWebtunnelClient("192.168.1.117:8811", &wsDialer,
		false, InitializeOS, true, 30)
	if err != nil {
		glog.Exitf("Failed to initialize client: %s", err)
	}

	// Start the client.
	if err := client.Start(); err != nil {
		glog.Exit(err)
	}

	select {
	case <-c:
		client.Stop()
		glog.Infoln("Shutting down WebTunnel")

	// client.Error channel returns errors that may be unrecoverable. The user can decide how to handle them.
	case err := <-client.Error:
		glog.Exitf("Client failure: %s", err)
	}
}
