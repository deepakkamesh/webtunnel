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
	daemonPort := 3344
	flag.Parse()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Initialize and Startup Webtunnel.
	glog.Warning("Starting WebTunnel...")
	wsDialer := websocket.Dialer{}
	wsDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client, err := webtunnelclient.NewWebtunnelClient("192.168.1.117:8811", &wsDialer, daemonPort)
	if err != nil {
		glog.Fatalf("Failed to initialize client: %s", err)
	}
	client.Start()

	<-c
	glog.Infoln("Shutting down WebTunnel")
	client.Stop()
}
