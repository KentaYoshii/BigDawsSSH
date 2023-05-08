package info

import (
	"net"
	protocol "ssh/pkg/protocol"
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

	// Protocol
	PVM *protocol.ProtocolVersionMessage

	// Name-Lists (comma-separated string)
	// Supported algorithm on the ssh server in the order of preference
	// The first in each of these is the "guessed" algorithm
	kex_algorithms                         string
	server_host_key_algorithms             string
	encryption_algorithms_client_to_server string
	encryption_algorithms_server_to_client string
	mac_algorithms_client_to_server        string
	mac_algorithms_server_to_client        string
	first_kex_packet_follows               bool
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
