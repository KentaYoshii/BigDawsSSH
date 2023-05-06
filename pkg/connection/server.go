package connection

import (
	"fmt"
	"net"
	protocol "ssh/pkg/protocol"
	info "ssh/pkg/info"
)


// --------          Server         --------

func CreateNewListener(service string) *net.TCPListener {
	port_str := fmt.Sprintf(":%s", service)
	tcpAddr, err := net.ResolveTCPAddr("tcp4", port_str)
	protocol.CheckError(err, "tcp4")
	listener, err := net.ListenTCP("tcp4", tcpAddr)
	protocol.CheckError(err, "tcp4")
	fmt.Printf("Server running at port %s\n", service)
	return listener;
}

func AcceptNewConnection(si *info.ServerInfo) *net.TCPConn {
	listenSocket := si.ListenerConn
	for {
		conn, err := listenSocket.AcceptTCP()
		if (protocol.CheckError(err, "AcceptTCP")) {
			continue
		}
		fmt.Printf("Connection accepted from %s\n", conn.RemoteAddr().String())

		// Add the new connection to the list of clients
		ci := info.CreateNewClientInfo(si.NewID, conn.RemoteAddr().String(), conn)
		si.ClientsMutex.Lock()
		si.Clients = append(si.Clients, ci)
		si.NewID++
		si.ClientsMutex.Unlock()

		// Start a goroutine to handle the connection
		go HandleConnection(si, ci)
	}
}

func HandleConnection(si *info.ServerInfo, ci *info.ClientInfo) {

}