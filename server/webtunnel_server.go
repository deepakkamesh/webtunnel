package main

import "log"

func main() {

	// Initialize the handlers/routers.
	router, err := NewRouter("en0")
	if err != nil {
		log.Fatalf("Failed to inialize Router %s", err)
	}
	wshandler := NewWSHandler("192.168.1.111:8811", router)

	// STart the servers
	go wshandler.Start()
	router.Start()
}
