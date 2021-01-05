package main

import (
	"flag"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
	"github.com/golang/glog"
	"github.com/songgao/water"
)

func main() {
	daemonPort := 3344
	flag.Parse()

	glog.Info("Starting ClientDaemon.. Waiting for Config from client..")

	// Initialize and Startup Client Daemon to handle network interface.
	daemon, err := webtunnelclient.NewClientDaemon(daemonPort, water.TUN, InitializeOS)
	if err != nil {
		glog.Exitf("Daemon Init failed:%v", err)
	}
	if err := daemon.Start(); err != nil {
		glog.Exitf("Failed start Daemon:%v", err)
	}

	select {
	case err := <-daemon.Error:
		glog.Exitf("Shutting down Daemon error %s", err)
	}
}
