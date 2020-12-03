package main

import (
	"fmt"
	"log"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
)

func main() {

	fmt.Println("Starting WebTunnel...")

	fmt.Println("Initialization Complete.")

	client, err := webtunnelclient.NewWebtunnelClient(2, "192.168.1.117:8811", true)
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
