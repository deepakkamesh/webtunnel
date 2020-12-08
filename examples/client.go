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
		}
	}
}
