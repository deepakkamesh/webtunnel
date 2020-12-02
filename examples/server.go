package main

import (
	"fmt"
	"log"

	"github.com/deepakkamesh/webtunnel/webtunnelserver"
)

func main() {

	fmt.Println("starting..")
	server, err := webtunnelserver.NewWebTunnelServer(2, "192.168.1.117:8811", "10.0.0.1", "255.255.255.0", "172.16.0.0/24", "10.0.0.0/24")
	if err != nil {
		log.Fatalf("%s", err)
	}

	server.Start()

	for {
		select {
		case err := <-server.Error:
			log.Println(err)

		case diag := <-server.Diag:
			log.Println(diag)

		}
	}
}
