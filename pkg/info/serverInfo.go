package info

import (
	"net"
	"sync"
	protocol "ssh/pkg/protocol"
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

	// Protocol
	PVM *protocol.ProtocolVersionMessage
}

func CreateNewServerInfo(hostname string, port string, listenerConn *net.TCPListener) *ServerInfo {
	return &ServerInfo{
		Hostname:     hostname,
		Port:         port,
		ListenerConn: listenerConn,
		NewID:        0,
		Clients:      make([]*ClientInfo, 0),
		CloseChan:    make(chan bool, 1),
		CmdChan:      make(chan []string),
		ClientsMutex: &sync.Mutex{},
		ClientWg:     &sync.WaitGroup{},
		PVM:          protocol.CreateProtocolVersionMessage(),
	}
}
