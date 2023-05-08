package connection

import (
	"fmt"
	"net"
	info "ssh/pkg/info"
	"os"
)

func CreateNewListener(service string) *net.TCPListener {
	port_str := fmt.Sprintf(":%s", service)
	tcpAddr, err := net.ResolveTCPAddr("tcp4", port_str)
	if err != nil {
		fmt.Println("ResolveTCPAddr failed:", err.Error())
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp4", tcpAddr)
	if err != nil {
		fmt.Println("ListenTCP failed:", err.Error())
		os.Exit(1)
	}
	fmt.Printf("Server running at port %s\n", service)

	return listener;
}

func AcceptNewConnection(si *info.ServerInfo) *net.TCPConn {
	listenSocket := si.ListenerConn
	for {
		conn, err := listenSocket.AcceptTCP()
		if err != nil {
			fmt.Println("Accept failed:", err.Error())
			os.Exit(1)
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

// function that gets called with "quit" command
func CloseConnection(si *info.ServerInfo) {
	for _, ci := range si.Clients {
		ci.Conn.Close()
	}
}

// function that gets called upon receiving a new connection
// exchange protocol version and other info with client
func ExchangeProtocolVersion(si *info.ServerInfo, ci *info.ServerClientInfo) bool {
	pvm := si.PVM
	conn := ci.Conn

	// send protocol version
	b := pvm.Marshall()
	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("Error sending protocol version:", err.Error())
		return false
	}

	// receive protocol version
	b = make([]byte, 256)
	_, err = conn.Read(b)
	if err != nil {
		fmt.Println("Error receiving protocol version:", err.Error())
		return false
	}

	// unmarshall and verify protocol version
	// comments returend here
	_, err = pvm.UnmarshallAndVerify(b)
	
	return err == nil
}

func HandleConnection(si *info.ServerInfo, ci *info.ServerClientInfo) {

	// exchange protocol version
	if !ExchangeProtocolVersion(si, ci) {
		fmt.Println("Protocol version exchange failed")
		return
	}
}