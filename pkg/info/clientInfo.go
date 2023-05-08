package info

import (
	"net"
)

type ServerClientInfo struct {
	// Server use
	ID      int
	Address string
	Conn    *net.TCPConn
	Status  int
}

func CreateNewClientInfo(id int, address string, conn *net.TCPConn) *ServerClientInfo {
	return &ServerClientInfo{
		ID:      id,
		Address: address,
		Conn:    conn,
		Status:  0,
	}
}
