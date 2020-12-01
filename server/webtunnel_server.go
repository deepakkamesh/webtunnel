package main

import (
	"fmt"
	"log"
)

func main() {

	// Initialize the handlers/routers.
	fmt.Printf("Starting WebTunnel Client")
	router, err := NewRouter("10.0.0.1", "255.255.255.0")
	if err != nil {
		log.Fatalf("Failed to inialize Router %s", err)
	}
	wshandler := NewWSHandler("192.168.1.117:8811", router)

	// Start the servers
	router.Start()
	wshandler.Start()
}
