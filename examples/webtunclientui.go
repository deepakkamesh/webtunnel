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
	ui              *gocui.Gui
	webtunclient    *webtunnelclient.WebtunnelClient
	switchableViews []string // List of switchable views.
	currView        int      // Current focused view.
}

func NewclientUI() *Clientui {
	// Initialize the GUI.
	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		glog.Exit(err)
	}

	// Initialize the client.
	client, err := webtunnelclient.NewWebtunnelClient("", &websocket.Dialer{},
		water.TUN, InitializeOS, true, 30)
	if err != nil {
		return nil
	}

	return &Clientui{
		ui:              g,
		webtunclient:    client,
		switchableViews: []string{"servers", "opt", "connect", "disconnect", "exit"},
		currView:        1,
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

					fmt.Fprintf(statusView, "Client failure: %s\n", cErr)
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

	g.SetCurrentView("connect")

	statusView, err := g.View("status")
	if err != nil {
		return err
	}
	optView, err := g.View("opt")
	if err != nil {
		return err
	}
	serverView, err := g.View("servers")
	if err != nil {
		return err
	}

	if c.webtunclient.IsInterfaceReady() {
		fmt.Fprintln(statusView, "Already connected. Disconnect first")
		return nil
	}
	statusView.Clear()

	// Get Selected servername.
	_, cy := serverView.Cursor()
	server, err := serverView.Line(cy)
	if err != nil {
		fmt.Fprintln(statusView, "Select a server")
		return nil
	}
	// Get log level.
	_, cy = optView.Cursor()
	log, err := optView.Line(cy)
	if err != nil {
		fmt.Fprintln(statusView, "Select a log level")
		return nil
	}

	fmt.Fprintf(statusView, "Setting log verbosity to %s...\n", log)

	wsDialer := websocket.Dialer{}
	wsDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// Start the client.
	fmt.Fprintf(statusView, "Connecting to %s...\n", server)
	c.webtunclient.SetServer(server, true, &wsDialer)
	if err := c.webtunclient.Start(); err != nil {
		fmt.Fprintln(statusView, err)
		return nil
	}
	// Wait for interface to be ready.
	for !c.webtunclient.IsInterfaceReady() {
	}
	fmt.Fprintln(statusView, "Connected. Webtunnel ready.")
	return nil
}

func (c *Clientui) disconnect(g *gocui.Gui, v1 *gocui.View) error {
	g.SetCurrentView("disconnect")
	v, err := g.View("status")
	if err != nil {
		return err
	}
	if !c.webtunclient.IsInterfaceReady() {
		fmt.Fprintln(v, "Not connected to WebTunnel")
		return nil
	}
	fmt.Fprintf(v, "Disconnecting...")
	if err := c.webtunclient.Stop(); err != nil {
		fmt.Fprintln(v, err)
		return nil
	}
	fmt.Fprintln(v, "Done")
	return nil
}

func (c *Clientui) quit(g *gocui.Gui, v *gocui.View) error {
	g.Close()
	return gocui.ErrQuit
}

func (c *Clientui) setKeyBindings() error {
	// Common bindings.
	if err := c.ui.SetKeybinding("", gocui.KeyTab, gocui.ModNone, c.switchView); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", gocui.KeyArrowDown, gocui.ModNone, c.cursorDown); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", gocui.KeyArrowUp, gocui.ModNone, c.cursorUp); err != nil {
		return err
	}
	// Connect bindings.
	if err := c.ui.SetKeybinding("connect", gocui.KeyEnter, gocui.ModNone, c.serverConnect); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("connect", gocui.MouseLeft, gocui.ModNone, c.serverConnect); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", 'C', gocui.ModNone, c.serverConnect); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", 'c', gocui.ModNone, c.serverConnect); err != nil {
		return err
	}
	// Disconnect bindings.
	if err := c.ui.SetKeybinding("disconnect", gocui.KeyEnter, gocui.ModNone, c.disconnect); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("disconnect", gocui.MouseLeft, gocui.ModNone, c.disconnect); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", 'D', gocui.ModNone, c.disconnect); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", 'd', gocui.ModNone, c.disconnect); err != nil {
		return err
	}
	// Exit bindings.
	if err := c.ui.SetKeybinding("exit", gocui.KeyEnter, gocui.ModNone, c.quit); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("exit", gocui.MouseLeft, gocui.ModNone, c.quit); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", 'X', gocui.ModNone, c.quit); err != nil {
		return err
	}
	if err := c.ui.SetKeybinding("", 'x', gocui.ModNone, c.quit); err != nil {
		return err
	}

	return nil
}

func (c *Clientui) switchView(g *gocui.Gui, v *gocui.View) error {
	if _, err := g.SetCurrentView(c.switchableViews[c.currView]); err != nil {
		return err
	}
	c.currView++
	if c.currView > len(c.switchableViews)-1 {
		c.currView = 0
	}
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
	g.Highlight = true
	g.SelFgColor = gocui.ColorRed

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
		v.Title = "Servers"
		v.Highlight = true
		v.FgColor = gocui.ColorGreen
		v.BgColor = gocui.ColorBlack
		v.SelBgColor = gocui.ColorGreen
		v.SelFgColor = gocui.ColorBlack
		fmt.Fprintln(v, "192.168.1.110:8811\nServer2")
		if _, err := g.SetCurrentView("servers"); err != nil {
			return err
		}
	}
	if v, err := g.SetView("opt", 0, maxY/2+1, maxX/3, maxY/2+4); err != nil {
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
	if v, err := g.SetView("connect", maxX/3+1, maxY-7, maxX/3+9, maxY-5); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.FgColor = gocui.ColorGreen
		fmt.Fprintln(v, "Connect")
	}
	if v, err := g.SetView("disconnect", maxX/3+10, maxY-7, maxX/3+21, maxY-5); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.FgColor = gocui.ColorMagenta
		fmt.Fprintln(v, "Disconnect")
	}
	if v, err := g.SetView("exit", maxX/3+22, maxY-7, maxX/3+27, maxY-5); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.FgColor = gocui.ColorBlue
		fmt.Fprintln(v, "eXit")
	}
	if v, err := g.SetView("metrics", maxX/3+28, maxY-7, maxX-1, maxY-5); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Metrics"
	}
	if v, err := g.SetView("keymap", 0, maxY-4, maxX-1, maxY-1); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Title = "Keyboard Shortcuts"
		v.Wrap = true
		fmt.Fprintln(v, "C - Connect | X - eXit | D - Disconnect |  Arrow Up/Down - Move Up/Down")
		fmt.Fprintln(v, " TAB - Switch between Server / Options")
	}

	return nil
}
