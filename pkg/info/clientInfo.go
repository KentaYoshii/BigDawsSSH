package info

import (
	"net"
)

type ClientInfo struct {
	ID      int
	Address string
	Conn    *net.TCPConn
	Status  int
}

func CreateNewClientInfo(id int, address string, conn *net.TCPConn) *ClientInfo {
	return &ClientInfo{
		ID:      id,
		Address: address,
		Conn:    conn,
		Status:  0,
	}
}
