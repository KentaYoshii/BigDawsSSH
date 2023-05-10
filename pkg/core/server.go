package connection

import (
	"fmt"
	"net"
	"os"
	info "ssh/pkg/info"
	proto "ssh/pkg/protocol"
	"ssh/util"
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

	return listener
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

	// marshall the server's stored protocol version message
	b := pvm.Marshall()

	// DSA sign protocol version message
	b = proto.SignServerDSA(b, si.DSAPrivKey)
	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("Error sending protocol version:", err.Error())
		return false
	}

	// receive protocol version message from client (raw) so max 256 bytes
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

func ExchangeNegotiationMessage(si *info.ServerInfo, ci *info.ServerClientInfo) bool {
	// send server's algorithm negotiation message

	// prepend the message type and cookie 
	// SSH_MSG_KEXINIT = 20 (1 byte)
	// cookie = 16 bytes
	cookie := proto.GenerateCookie()

	b := make([]byte, 0)
	b = append(b, util.SSH_MSG_KEXINIT)
	b = append(b, cookie...)

	sanm := proto.CreateServerAlgorithmNegotiationMessage()
	sanm.Kex_algorithms = si.Kex_algorithms
	sanm.Server_host_key_algorithms = si.Server_host_key_algorithms
	sanm.Encryption_algorithms_server_to_client = si.Encryption_algorithms_server_to_client
	sanm.Mac_algorithms_server_to_client = si.Mac_algorithms_server_to_client
	sanm.Compression_algorithms_server_to_client = si.Compression_algorithms_server_to_client
	sanm.Languages_server_to_client = si.Languages_server_to_client
	sanm.First_kex_packet_follows = false

	msg_b := sanm.Marshall()
	b = append(b, msg_b...)

	b = proto.SignServerDSA(b, si.DSAPrivKey)
	_, err := ci.Conn.Write(b)
	if err != nil {
		fmt.Println("Error sending algorithm negotiation message:", err.Error())
		return false
	}

	// receive client's algorithm negotiation message
	b = make([]byte, 256)
	_, err = ci.Conn.Read(b)
	if err != nil {
		fmt.Println("Error receiving algorithm negotiation message:", err.Error())
		return false
	} 

	// unmarshall client's negotiation message
	canm, err := proto.UnmarshallClientNegotiation(b)
	if err != nil {
		fmt.Println("Error unmarshalling client's algorithm negotiation message:", err.Error())
		return false
	}

	// do the algorithm negotiation
	agreed, err := proto.DoNegotiation(canm, sanm)
	if err != nil {
		fmt.Println("Error doing algorithm negotiation:", err.Error())
		return false
	}

	si.ClientsMutex.Lock()
	si.ClientsAlgorithms[ci.ID] = agreed
	si.ClientsMutex.Unlock()

	return true
}

func HandleConnection(si *info.ServerInfo, ci *info.ServerClientInfo) {

	// exchange protocol version
	if !ExchangeProtocolVersion(si, ci) {
		fmt.Println("Protocol version exchange failed")
		// close connection
		ci.Conn.Close()
		return
	}

	fmt.Println("Protocol version exchange successful with client", ci.ID)


	// exchange algorithm negotiation message
	if !ExchangeNegotiationMessage(si, ci) {
		fmt.Println("Algorithm negotiation failed")
		// close connection
		ci.Conn.Close()
		return
	}

	fmt.Println("Algorithm negotiation successful with client", ci.ID)

	// key exchange

	if !proto.Do_KEX_Server(si.ClientsAlgorithms[ci.ID].Kex_algorithm)(ci.Conn) {
		fmt.Println("Key exchange failed")
		// close connection
		ci.Conn.Close()
		return
	}

	fmt.Println("Key exchange successful with client", ci.ID)
}
