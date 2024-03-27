// server.go - Example webtunnel server implementation.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/deepakkamesh/webtunnel/webtunnelserver"
	"github.com/golang/glog"
)

type myHandle struct{}

func (h *myHandle) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "This is a custom Handler")
}

// SigNotify catches interrupts.
func SigNotify(c chan os.Signal) {
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGINT)
}

func main() {
	// Get some flags.
	listenAddr := flag.String("listenAddr", ":8811", "Bind address:port")
	httpsKeyFile := flag.String("httpsKeyFile", "localhost.key", "HTTPS Key file path")
	httpsCertFile := flag.String("httpsCertFile", "localhost.crt", "HTTPS Cert file path")

	gwIP := flag.String("gwIP", "192.168.0.1", "Server GW IP for the VPN tunnel")
	tunNetmask := flag.String("tunNetmask", "255.255.255.0", "Server GW IP for the VPN tunnel")
	clientNetPrefix := flag.String("clientNetPrefix", "192.168.0.0/24", "Server GW IP for the VPN tunnel")
	routePrefix := flag.String("routePrefix","172.16.0.1/30", "routes advertised by server separated by comma")

	routes := strings.Split(*routePrefix,",")

	flag.Parse()

	glog.Info("starting webtunnel server..")
	server, err := webtunnelserver.NewWebTunnelServer(*listenAddr, *gwIP,
		*tunNetmask, *clientNetPrefix, []string{"8.8.8.8", "8.8.1.1"},
		routes, true, *httpsKeyFile, *httpsCertFile)
	if err != nil {
		glog.Fatalf("%s", err)
	}

	// Set Custom HTTP Handlers if you want to handle any custom HTTP endpoints for additional functions.
	if err := server.SetCustomHandler("/hello", new(myHandle)); err != nil {
		glog.Exit(err)
	}

	// Start the server.
	server.Start()

	// Catch interrupts.
	c := make(chan os.Signal, 1)
	SigNotify(c)

	// Print Metrics.
	t := time.NewTicker(30 * time.Second)
	go func() {
		for {
			<-t.C
			m := server.GetMetrics()
			glog.Infof("Metrics Users:%v, Bytes: %v/s, Packets:%v/s", m.Users, m.Bytes/30, m.Packets/30)
			server.ResetMetrics()
		}
	}()

	// server.Error has any unrecoverable errors that can be handled.
	for {
		select {
		case err := <-server.Error:
				glog.Exitf("Shutting down server %v", err)
		case <-c:
				glog.Info("Caught Interrupt!")
				server.Stop() // this will send an error in the Error channel
		}
	}
}

