package info

import (
	"net"
	"sync"
)

type ServerInfo struct {
	// Basic info a/b the server
	Hostname     string
	Port         string
	ListenerConn *net.TCPListener

	// Info about the clients
	NewID   int
	Clients []*ClientInfo

	// Channels
	CloseChan chan bool
	CmdChan   chan []string

	// Mutexes
	ClientsMutex *sync.Mutex
	ClientWg     *sync.WaitGroup
}

func CreateNewServerInfo(hostname string, port string, listenerConn *net.TCPListener) *ServerInfo {
	return &ServerInfo{
		Hostname:     hostname,
		Port:         port,
		ListenerConn: listenerConn,
		NewID:        0,
		Clients:      make([]*ClientInfo, 0),
		CloseChan:    make(chan bool),
		CmdChan:      make(chan []string),
	}
}