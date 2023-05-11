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
	cliPVM, _, err := pvm.UnmarshallAndVerify(b)
	if err != nil {
		fmt.Println("Error unmarshalling and verifying protocol version:", err.Error())
		return false
	}

	// store client's protocol version message
	ci.PVM = cliPVM

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
	si.KInitMSG = b
	b = proto.SignServerDSA(b, si.DSAPrivKey)

	// Binary Packet Protocol
	binPacket := proto.CreateBinPacket(b, 16)
	b = binPacket.Marshall()
	_, err := ci.Conn.Write(b)
	if err != nil {
		fmt.Println("Error sending algorithm negotiation message:", err.Error())
		return false
	}
	retry:
	// receive client's algorithm negotiation message
	b = make([]byte, util.MAX_PACKET_SIZE)
	_, err = ci.Conn.Read(b)
	if err != nil {
		fmt.Println("Error receiving algorithm negotiation message:", err.Error())
		return false
	}

	binPacket, _ = proto.UnmarshallBinaryPacket(b)
	b = binPacket.Payload
	// check msg type
	m_type := b[0]
	// ignore message
	if m_type == util.SSH_MSG_IGNORE || m_type == util.SSH_MSG_DEBUG {
		goto retry
	} else if m_type == util.SSH_MSG_DISCONNECT {
		fmt.Println("Received disconnec message")
		return false
	} 

	// unmarshall client's negotiation message
	canm, len, err := proto.UnmarshallClientNegotiation(b)
	if err != nil {
		fmt.Println("Error unmarshalling client's algorithm negotiation message:", err.Error())
		return false
	}

	ci.ClientKInitMSG = b[:len+1]

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

func ExchangeServiceMessage(si *info.ServerInfo, ci *info.ServerClientInfo) bool {

	enc_algo := si.ClientsAlgorithms[ci.ID].Encryption_algorithm
	mac_algo := si.ClientsAlgorithms[ci.ID].Mac_algorithm

	// read service request message
	retry:
	b := make([]byte, util.MAX_PACKET_SIZE)
	_, err := ci.Conn.Read(b)
	if err != nil {
		fmt.Println("Error receiving service request message:", err.Error())
		return false
	}
	recvEncryptedPacket, _ := proto.UnmarshallEncryptedBinaryPacket(b)
	binPacket, err := proto.DecryptAndVerify(recvEncryptedPacket, ci.Keys.EncKey_C2S,
		ci.Keys.IntKey_C2S, ci.Keys.IV_C2S, ci.ClientSeqNum, enc_algo, mac_algo)
	if err != nil {
		fmt.Println("Error decrypting and verifying service request message:", err.Error())
		return false
	}

	b = binPacket.Payload
	m_type := b[0]
	if m_type == util.SSH_MSG_IGNORE || m_type == util.SSH_MSG_DEBUG {
		goto retry
	} else if m_type == util.SSH_MSG_DISCONNECT {
		fmt.Println("Received disconnec message")
		return false
	} 
	
	ci.ClientSeqNum++
	reqMsg := proto.UnmarshallServiceRequest(b)

	if reqMsg.MessageType != util.SSH_MSG_SERVICE_REQUEST {
		fmt.Println("Message type not SSH_MSG_SERVICE_REQUEST")
		return false
	}
	if reqMsg.ServiceName != "ssh-userauth" {
		fmt.Println("Service request message not for ssh-userauth")
		return false
	}

	// send service accept message
	sam := &proto.ServiceAcceptMessage{
		MessageType: util.SSH_MSG_SERVICE_ACCEPT,
		ServiceName: "ssh-userauth",
	}

	b = sam.Marshall()
	binPacket = proto.CreateBinPacket(b, uint32(ci.BLK_SIZE))
	encryptedPacket, err := proto.EncryptAndMac(binPacket, ci.Keys.EncKey_S2C, 
		ci.Keys.IntKey_S2C, ci.Keys.IV_S2C, ci.ServerSeqNum, enc_algo, mac_algo)
	if err != nil {
		fmt.Println("Error encrypting and macing service accept message:", err.Error())
		return false
	}

	b = encryptedPacket.Marshall()
	_, err = ci.Conn.Write(b)
	if err != nil {
		fmt.Println("Error sending service accept message:", err.Error())
		return false
	}

	ci.ServerSeqNum++

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
	ci.BLK_SIZE = util.GetBlockSize(si.ClientsAlgorithms[ci.ID].Encryption_algorithm)
	kex_algo := si.ClientsAlgorithms[ci.ID].Kex_algorithm
	group := proto.GetDHGroup(kex_algo)

	k, exh, suc := proto.Do_KEX_Server(si.ClientsAlgorithms[ci.ID].Kex_algorithm)(ci.Conn, group,
		si.PVM, ci.PVM, si.KInitMSG, ci.ClientKInitMSG,
		si.DSAPubKey, si.DSAPrivKey)

	if !suc {
		fmt.Println("Key exchange failed")
		// close connection
		ci.Conn.Close()
		return
	}

	// store shared secret and exchange hash
	ci.SharedSecret = k
	ci.ExchangeHash = exh
	ci.SessionIdentifier = exh

	ci.Status = "KEXed"

	fmt.Println("Key exchange successful with client", ci.ID)

	newKs := proto.GenerateNewKeys(k, exh, ci.SessionIdentifier, si.ClientsAlgorithms[ci.ID].Encryption_algorithm)
	ci.Keys = newKs

	fmt.Println("New keys generated for client", ci.ID)

	// send New Key Message to client
	if !proto.ServerSendRecvNewKeyMessage(ci.Conn, si.DSAPrivKey) {
		fmt.Println("Error sending New Key Message to client", ci.ID)
		// close connection
		ci.Conn.Close()
		return
	}

	fmt.Println("New Key Message exchanged with client", ci.ID)

	ci.ServerSeqNum = 0
	ci.ClientSeqNum = 0

	// exchange service request message
	if !ExchangeServiceMessage(si, ci) {
		fmt.Println("Service request exchange failed")
		// close connection
		ci.Conn.Close()
		return
	}

	fmt.Println("Service request exchange successful with client", ci.ID)

}
