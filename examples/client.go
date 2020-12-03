package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
	"github.com/gorilla/websocket"
)

func main() {

	fmt.Println("Starting WebTunnel...")

	fmt.Println("Initialization Complete.")

	wsDialer := websocket.Dialer{}
	wsDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client, err := webtunnelclient.NewWebtunnelClient(2, "192.168.1.117:8811", &wsDialer)
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
