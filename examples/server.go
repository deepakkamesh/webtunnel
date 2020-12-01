package main

import (
	"log"

	"github.com/deepakkamesh/webtunnel/webtunnelserver"
)

func main() {

	server, err := webtunnelserver.NewWebTunnelServer(true, "192.168.1.112:8811", "10.0.0.1", "255.255.255.0")
	if err != nil {
		log.Fatalf("%s", err)
	}

	select {
	case err := <-server.Error:
		log.Println(err)

	case diag := <-server.Diag:
		log.Println(diag)

	}
}
