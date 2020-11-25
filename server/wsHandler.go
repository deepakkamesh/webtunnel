package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

// upgrader variable provides options when upgrading HTTP to Websocket. The Dialer uses a default
// size of 4096 when a buffer size field is set to zero. The HTTP server buffers have a size of
// 4096 at the time of this writing.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

type WSPkt struct {
	payload []byte
}

type WSHandler struct {
	HTTPAddr string // Binding address of HTTP port.
	router   *Router
}

func NewWSHandler(HTTPAddr string, router *Router) *WSHandler {

	return &WSHandler{
		HTTPAddr: HTTPAddr,
		router:   router,
	}
}

// Start function to start the http handlers and tcp connection.
func (r *WSHandler) Start() {
	http.HandleFunc("/", r.httpEndpoint)
	http.HandleFunc("/ws", r.wsEndpoint)
	log.Fatal(http.ListenAndServe(r.HTTPAddr, nil))
}

// wsEndpoint defines HTTP Websocket Path and upgrades the HTTP connection.
func (r *WSHandler) wsEndpoint(w http.ResponseWriter, rcv *http.Request) {

	// Upgrade HTTP connection to a WebSocket connection.
	conn, err := upgrader.Upgrade(w, rcv, nil)
	if err != nil {
		log.Printf("Error upgrading to websocket: %s\n", err)
		return
	}
	defer conn.Close()

	// Add connection to Router.
	r.router.NewConn(conn)
	// TODO: Handle close connection.
	conn.SetCloseHandler(
		func(code int, text string) error {
			log.Printf("Connection closed %v %v", code, text)
			return nil
		})

	// Process messages from websocket to Router.
	for {
		mt, message, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Error reading from websocket for %s: %s ", rcv.RemoteAddr, err)
			return
		}
		if mt != websocket.BinaryMessage {
			log.Printf("Unexpected message type. Closing Conn")
			return
		}
		r.router.WSData <- WSPkt{message}
	}
}

// httpEndpoint defines the HTTP / Path. The "Sender" will send an initial request to this URL.
func (r *WSHandler) httpEndpoint(w http.ResponseWriter, rcv *http.Request) {
	fmt.Fprint(w, "OK")
}
