/*
* Client for WebSocket VPN
 */
package main

import (
	"fmt"
	"log"
	"net/url"
	"os/exec"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

func main() {

	wsclient, err := NewWSClient("192.168.1.111:8811")
	if err != nil {
		log.Fatalf("initializing websocket failed %s", wsclient.RemoteWSAddr)
	}

	ifce, err := NewIface(wsclient)
	if err != nil {
		log.Fatalf("initializing network failed %s", err)
	}

	wsclient.SetIfaceConn(ifce.Ifce)
	ifce.ProcessTUNPacket()
}

type WSClient struct {
	RemoteWSAddr string
	wsconn       *websocket.Conn
	iconn        *water.Interface
}

func NewWSClient(remoteAddr string) (*WSClient, error) {
	u := url.URL{Scheme: "ws", Host: remoteAddr, Path: "/ws"}
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}

	return &WSClient{
		RemoteWSAddr: remoteAddr,
		wsconn:       c,
	}, nil
}

func (w *WSClient) SetIfaceConn(c *water.Interface) {
	w.iconn = c
}

func (w *WSClient) ProcessWSPacket() {
	for {
		mt, pkt, err := w.wsconn.ReadMessage()
		if err != nil {
			log.Fatalf("read error %s", err)
		}
		if mt != websocket.BinaryMessage {
			log.Fatalf("Unknown message type")
		}

		fmt.Println("recv WS", gopacket.NewPacket(
			pkt,
			layers.LayerTypeIPv4,
			gopacket.Default,
		))

		if _, err := w.iconn.Write(pkt); err != nil {
			log.Fatalf("error writing on socket %s", err)
		}
	}
}

/***********Iface**********/
type Iface struct {
	Ifce *water.Interface
	ws   *WSClient
}

func NewIface(ws *WSClient) (*Iface, error) {

	// Create TUN interface.
	ifce, err := water.New(water.Config{
		DeviceType: water.TUN,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating TUN int %s", err)
	}

	// Assign IP.
	// TODO: Handle other Operating Systems and add routing for network prefixs.
	if err := exec.Command("/sbin/ifconfig", ifce.Name(), "10.0.0.2", "10.0.0.1", "up").Run(); err != nil {
		return nil, fmt.Errorf("error setting ip on tun %s", err)
	}

	return &Iface{
		Ifce: ifce,
		ws:   ws,
	}, nil
}

func (i *Iface) ProcessTUNPacket() {
	pkt := make([]byte, 2000)
	for {
		_, err := i.Ifce.Read(pkt)
		if err != nil {
			log.Fatal(err)
		}
		if i.ws.wsconn == nil {
			log.Fatalf("Invalid websocket connection")
		}
		if err := i.ws.wsconn.WriteMessage(websocket.BinaryMessage, pkt); err != nil {
			log.Fatalf("error trying to write message to websocket: %s", err)
		}
		fmt.Println("recv TUN", gopacket.NewPacket(
			pkt,
			layers.LayerTypeIPv4,
			gopacket.Default,
		))

	}
}
