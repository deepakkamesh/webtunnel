// server.go - Example webtunnel server implementation.
package main

import (
	"flag"
	"time"

	"github.com/deepakkamesh/webtunnel/webtunnelserver"
	"github.com/golang/glog"
)

func main() {
	// Get some flags.
	listenAddr := flag.String("listenAddr", ":8811", "Bind address:port")
	httpsKeyFile := flag.String("httpsKeyFile", "localhost.key", "HTTPS Key file path")
	httpsCertFile := flag.String("httpsCertFile", "localhost.crt", "HTTPS Cert file path")

	flag.Parse()

	glog.Info("starting webtunnel server..")
	server, err := webtunnelserver.NewWebTunnelServer(*listenAddr, "192.168.0.1",
		"255.255.255.0", "192.168.0.0/24", []string{"8.8.8.8", "8.8.1.1"},
		[]string{"172.16.0.1/30"}, true, *httpsKeyFile, *httpsCertFile)
	if err != nil {
		glog.Fatalf("%s", err)
	}
	server.Start()

	/*
		glog.Info("starting DNS Forwarder..")
		dns, err := webtunnelserver.NewDNSForwarder("192.168.0.1", 53)
		if err != nil {
			glog.Fatal(err)
		}
		dns.Start()
	*/

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
	err = <-server.Error
	glog.Exitf("Shutting down server %v", err)
}
