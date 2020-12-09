package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
	"github.com/deepakkamesh/webtunnel/webtunnelcommon"
	"github.com/golang/glog"
)

func main() {
	daemonPort := 3344
	flag.Parse()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	glog.Info("Starting ClientDaemon.. Waiting for Config from client..")

	// Initialize and Startup Client Daemon to handle network interface.
	daemon, err := webtunnelclient.NewClientDaemon(daemonPort, webtunnelcommon.DiagLevelDebug)
	if err != nil {
		glog.Fatalf("Daemon Init failed:%v", err)
	}
	if err := daemon.Start(); err != nil {
		glog.Fatalf("Failed start Daemon:%v", err)
	}

	<-c
	glog.Infoln("Shutting down ClientDaemon")
}
