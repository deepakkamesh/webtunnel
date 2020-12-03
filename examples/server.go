package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/deepakkamesh/webtunnel/webtunnelserver"
)

func main() {
	// Get some flags.
	listenAddr := flag.String("listenAddr", "192.168.1.117:8811", "Bind address:port")
	httpsKeyFile := flag.String("httpsKeyFile", "", "HTTPS Key file path")
	httpsCertFile := flag.String("httpsCertFile", "", "HTTPS Cert file path")

	flag.Parse()

	fmt.Println("starting..")
	server, err := webtunnelserver.NewWebTunnelServer(2, *listenAddr, "192.168.0.1",
		"255.255.255.0", "172.16.0.0/24", "192.168.0.0/24", *httpsKeyFile, *httpsCertFile)
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
