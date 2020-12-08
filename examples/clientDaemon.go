package main

import (
	"fmt"
	"log"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
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
	for {
		select {
		case diag := <-daemon.Diag:
			log.Println(diag)
		case err := <-daemon.Error:
			log.Println(err)
		}
	}
}
