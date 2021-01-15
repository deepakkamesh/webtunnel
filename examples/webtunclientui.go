package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"time"

	"github.com/deepakkamesh/webtunnel/webtunnelclient"
	"github.com/golang/glog"
	"github.com/gorilla/websocket"
	"github.com/jroimartin/gocui"
	"github.com/songgao/water"
)

func main() {
	flag.Parse()
	clientui := NewclientUI()
	if err := clientui.InitUI(); err != nil {
		glog.Exit(err)
	}
	if err := clientui.Run(); err != nil {
		glog.Fatal(err)
	}
}

type Clientui struct {
	ui           *gocui.Gui
	webtunclient *webtunnelclient.WebtunnelClient
}

func NewclientUI() *Clientui {
	// Initialize the GUI.
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		glog.Exit(err)
	}

	// Create a dialer with options.
	wsDialer := websocket.Dialer{}
	wsDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// Initialize the client.
	client, err := webtunnelclient.NewWebtunnelClient("", &wsDialer,
		water.TUN, InitializeOS, true, 30)
	if err != nil {
		return nil
	}

	return &Clientui{
		ui:           g,
		webtunclient: client,
	}
}

func (c *Clientui) InitUI() error {
	c.ui.Cursor = true
	c.ui.Mouse = true
	c.ui.SetManagerFunc(layout)
	if err := c.setKeyBindings(); err != nil {
		return err
	}
	return nil
}

func (c *Clientui) Run() error {

	// Goroutine to handle errors from webtun client and metrics.
	go func() {
		time.Sleep(2 * time.Second) // Wait for mainloop to be ready.
		ticker := time.NewTicker(30 * time.Second)

		for {
			select {
			case <-ticker.C:
				pkt, bytes := c.webtunclient.GetMetrics()
				c.ui.Update(func(g *gocui.Gui) error {
					metricsView, err := g.View("metrics")
					if err != nil {
						return err
					}
					metricsView.Clear()
					fmt.Fprintf(metricsView, "Bytes:%v/s Packets:%v/s", bytes/30, pkt/30)
					return nil
				})
				c.webtunclient.ResetMetrics()

			// client.Error channel returns errors that may be unrecoverable.
			// The user can decide how to handle them.
			case cErr := <-c.webtunclient.Error:
				c.ui.Update(func(g *gocui.Gui) error {
					statusView, err := c.ui.View("status")
					if err != nil {
						return err
					}

					fmt.Fprintf(statusView, "Client failure: %s", cErr)
					fmt.Fprintln(statusView, "")
					return nil
				})
			}
		}
	}()

	// Mainloop is blocking.
	if err := c.ui.MainLoop(); err != nil && err != gocui.ErrQuit {
		glog.Exit(err)
	}
	return nil
}

func (c *Clientui) serverConnect(g *gocui.Gui, v *gocui.View) error {

	statusView, err := g.View("status")
	if err != nil {
		return err
	}

	if c.webtunclient.IsInterfaceReady() {
		fmt.Fprintln(statusView, "Already connected. Disconnect first")
		return nil
	}
	statusView.Clear()

	// Get Selected servername.
	_, cy := v.Cursor()
	server, err := v.Line(cy)
	if err != nil {
		fmt.Fprintln(statusView, "Select a server")
		return nil
	}

	// Get log verbosity level.
	optView, err := g.View("opt")
	if err != nil {
		return err
	}
	_, cy = optView.Cursor()
	log, err := optView.Line(cy)
	if err != nil {
		fmt.Fprintln(statusView, "Select a log level")
		return nil
	}

	fmt.Fprintf(statusView, "Setting log verbosity to %s...", log)
	fmt.Fprintln(statusView, "")

	// Start the client.
	fmt.Fprintf(statusView, "Connecting to %s...", server)
	fmt.Fprintln(statusView, "")
	c.webtunclient.SetServer(server, true)
	if err := c.webtunclient.Start(); err != nil {
		fmt.Fprintln(statusView, err)
		return nil
	}
	// Wait for interface to be ready.
	for !c.webtunclient.IsInterfaceReady() {
	}
	fmt.Fprintf(statusView, "Connected. Webtunnel ready.")
	fmt.Fprintln(statusView, "")
	return nil
}

func (c *Clientui) disconnect(g *gocui.Gui, v1 *gocui.View) error {

	v, err := g.View("status")
	if err != nil {
		return err
	}
	fmt.Fprintf(v, "Disconnecting...")
	if err := c.webtunclient.Stop(); err != nil {
		if err == websocket.ErrCloseSent {
			fmt.Fprintln(v, "Connection already closed")
			return nil
		}
		fmt.Fprintln(v, err)
	}
	fmt.Fprintln(v, "Done")
	return nil
}

func (c *Clientui) quit(g *gocui.Gui, v *gocui.View) error {
	g.Close()
	return gocui.ErrQuit
}

func (c *Clientui) setKeyBindings() error {
	if err := c.ui.SetKeybinding("", gocui.KeyCtrlX, gocui.ModNone, c.quit); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", gocui.KeyArrowDown, gocui.ModNone, c.cursorDown); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", gocui.KeyArrowUp, gocui.ModNone, c.cursorUp); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("servers", gocui.KeyEnter, gocui.ModNone, c.serverConnect); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("servers", gocui.MouseLeft, gocui.ModNone, c.serverConnect); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", gocui.KeyTab, gocui.ModNone, c.switchView); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", gocui.KeyCtrlD, gocui.ModNone, c.disconnect); err != nil {
		return err
	}
	return nil
}

func (c *Clientui) switchView(g *gocui.Gui, v *gocui.View) error {
	if v.Name() == "servers" {
		g.SetCurrentView("opt")
		return nil
	}
	g.SetCurrentView("servers")
	return nil
}

func (c *Clientui) cursorDown(g *gocui.Gui, v *gocui.View) error {
	if v == nil {
		return nil
	}
	// If the next line if blank do not move down.
	cx, cy := v.Cursor()
	data, err := v.Line(cy + 1)
	if err != nil {
		return err
	}
	if data == "" {
		return nil
	}
	// Move the cursor down.
	if err := v.SetCursor(cx, cy+1); err != nil {
		ox, oy := v.Origin()
		if err := v.SetOrigin(ox, oy+1); err != nil {
			return err
		}
	}

	return nil
}

func (c *Clientui) cursorUp(g *gocui.Gui, v *gocui.View) error {
	if v == nil {
		return nil
	}
	ox, oy := v.Origin()
	cx, cy := v.Cursor()
	if err := v.SetCursor(cx, cy-1); err != nil && oy > 0 {
		if err := v.SetOrigin(ox, oy-1); err != nil {
			return err
		}
	}
	return nil
}

func layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()

	if v, err := g.SetView("title", maxX/2-8, 0, maxX/2+11, 2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.FgColor = gocui.ColorBlue | gocui.AttrBold
		v.Frame = true
		fmt.Fprintln(v, " WEBTUNNEL CLIENT")
	}

	if v, err := g.SetView("servers", 0, 3, maxX/3, maxY/2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Server"
		v.Highlight = true
		v.FgColor = gocui.ColorGreen
		v.BgColor = gocui.ColorBlack
		v.SelBgColor = gocui.ColorGreen
		v.SelFgColor = gocui.ColorBlack
		fmt.Fprintln(v, "192.168.1.117:8811\nServer2")
		if _, err := g.SetCurrentView("servers"); err != nil {
			return err
		}
	}
	if v, err := g.SetView("opt", 0, maxY/2+1, maxX/3, maxY-5); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Options"
		v.Highlight = true
		v.FgColor = gocui.ColorGreen
		v.BgColor = gocui.ColorBlack
		v.SelBgColor = gocui.ColorGreen
		v.SelFgColor = gocui.ColorBlack
		fmt.Fprintln(v, "Log Verbosity - Normal")
		fmt.Fprintln(v, "Log Verbosity - High")
	}

	if v, err := g.SetView("status", maxX/3+1, 3, maxX-1, maxY-8); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Autoscroll = true
		v.Wrap = true
		v.Title = "Status"
	}
	if v, err := g.SetView("metrics", maxX/3+1, maxY-7, maxX-1, maxY-5); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Metrics"
		fmt.Fprintln(v, "Metrics")
	}

	if v, err := g.SetView("keymap", 0, maxY-4, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Keyboard Shortcuts"
		v.Wrap = true
		fmt.Fprintln(v, "<Ctrl+X> - Exit | <Ctrl+D> - Disconnect |  ArrowUp/ArrowDown - Move up/down | Enter - Connect")
		fmt.Fprintln(v, " TAB - Switch between Server / Options")
	}

	_ = maxY
	return nil
}
