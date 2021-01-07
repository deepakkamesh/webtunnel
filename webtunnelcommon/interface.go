package webtunnelcommon

import "io"

// Interface represents the network interface.
type Interface interface {
	io.ReadWriteCloser
	IsTUN() bool
	IsTAP() bool
	Name() string
}
