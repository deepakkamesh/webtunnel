package main

import (
	"flag"

	"github.com/deepakkamesh/webtunnel/webtunnelserver"
	"github.com/golang/glog"
)

func main() {
	// Get some flags.
	/*	listenAddr := flag.String("listenAddr", "192.168.1.117:8811", "Bind address:port")
		httpsKeyFile := flag.String("httpsKeyFile", "", "HTTPS Key file path")
		httpsCertFile := flag.String("httpsCertFile", "", "HTTPS Cert file path")

		flag.Parse()

		glog.Info("starting webtunnel server..")
			server, err := webtunnelserver.NewWebTunnelServer(*listenAddr, "192.168.0.1",
				"255.255.255.0", "192.168.0.0/24", "172.16.0.0/24", *httpsKeyFile, *httpsCertFile)
			if err != nil {
				glog.Fatalf("%s", err)
			}
			server.Start()*/
	flag.Parse()
	dns, err := webtunnelserver.NewDNSForwarder("192.168.1.117", 53)
	if err != nil {
		glog.Fatal(err)
	}
	if err := dns.Start(); err != nil {
		glog.Fatal(err)
	}
	for {
	}
}
