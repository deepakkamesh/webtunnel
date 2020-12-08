package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/gorilla/websocket"
)

func main() {
	daemonPort := 3344
	fmt.Println("Starting ClientDaemon...")
	// Initialize and Startup Client Daemon to handle network interface.
	daemon, err := webtunnelclient.NewClientDaemon(daemonPort, webtunnelcommon.DiagLevelDebug)
	if err != nil {
		log.Fatalf("Daemon Init failed:%v", err)
	}
	if err := daemon.Start(); err != nil {
		log.Fatalf("Failed start Daemon:%v", err)
	}

	// Initialize and Startup Webtunnel.
	fmt.Println("Starting WebTunnel...")
	wsDialer := websocket.Dialer{}
	wsDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client, err := webtunnelclient.NewWebtunnelClient(webtunnelcommon.DiagLevelDebug, "192.168.1.117:8811", &wsDialer, daemonPort)
	if err != nil {
		log.Fatalf("err %s", err)
	}
	client.Start()

	for {
		select {
		case diag := <-client.Diag:
			log.Println(diag)
		case err := <-client.Error:
			log.Println(err)
		case diag := <-daemon.Diag:
			log.Println(diag)
		case err := <-daemon.Error:
			log.Println(err)
		}
	}
}
