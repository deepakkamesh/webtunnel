package webtunnelcommon

import "io"

type Interface interface {
	io.ReadWriteCloser
	IsTUN() bool
	IsTAP() bool
	Name() string
}
