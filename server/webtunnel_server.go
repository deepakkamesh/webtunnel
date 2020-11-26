package main

import (
	"fmt"
	"log"
)

func main() {

	// Initialize the handlers/routers.
	fmt.Printf("Starting WebTunnel Client")
	router, err := NewRouter("wlo1")
	if err != nil {
		log.Fatalf("Failed to inialize Router %s", err)
	}
	wshandler := NewWSHandler("192.168.1.112:8811", router)

	// Start the servers
	go wshandler.Start()
	router.Start()
	for {
	}
}
