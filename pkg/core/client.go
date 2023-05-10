package connection

import (
	"fmt"
	"net"
	"ssh/pkg/info"
	proto "ssh/pkg/protocol"
	"ssh/util"
)

func DoConnect(s_address string, s_port string) (*net.TCPConn, error) {
	addr_str := fmt.Sprintf("%s:%s", s_address, s_port)
	addr_str_n, err := net.ResolveTCPAddr("tcp4", addr_str)
	if err != nil {
		fmt.Println("ResolveTCPAddr failed:", err.Error())
		return nil, err
	}
	conn, err := net.DialTCP("tcp4", nil, addr_str_n)
	if err != nil {
		fmt.Println("Dial failed:", err.Error())
		return nil, err
	}
	return conn, nil
}

func DoProtocolVersionExchange(csi *info.ClientServerInfo) bool {

	conn := csi.ServerConn
	dsaPubKey := csi.ServerDSAPubKey

	// create client's protocol version message
	client_pvm := proto.CreateProtocolVersionMessage()

	// send client's protocol version raw
	b := client_pvm.Marshall()
	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	// read server's protocol version which should be digitally signed with server's DSA private key
	buf := make([]byte, 1024)
    _, err = conn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}

	// DSA verify server's message
	msg, suc := proto.VerifyServerDSASignature(buf, dsaPubKey)
	if !suc {
		fmt.Println("DSA Verify failed")
		return false
	} 
	// unmarshall server's protocol version
	_, err = client_pvm.UnmarshallAndVerify(msg)

	return err == nil
}

func DoAlgorithmNegotiation(csi *info.ClientServerInfo, cci *info.ClientClientInfo) bool {

	conn := csi.ServerConn
	dsaPubKey := csi.ServerDSAPubKey

	// Create client's algorithm negotiation message
	canm := proto.CreateClientAlgorithmNegotiationMessage()
	// Populate client's algorithm negotiation message
	canm.Kex_algorithms = cci.Kex_algorithms
	canm.Server_host_key_algorithms = cci.Server_host_key_algorithms
	canm.Encryption_algorithms_client_to_server = cci.Encryption_algorithms_client_to_server
	canm.Mac_algorithms_client_to_server = cci.Mac_algorithms_client_to_server
	canm.Compression_algorithms_client_to_server = cci.Compression_algorithms_client_to_server
	canm.Languages_client_to_server = cci.Languages_client_to_server
	canm.First_kex_packet_follows = cci.First_kex_packet_follows

	// header
	head := make([]byte, 17)
	head[0] = util.SSH_MSG_KEXINIT
	// cookie
	cookie := proto.GenerateCookie()
	copy(head[1:17], cookie[:])

	// Send client's algorithm negotiation message
	msg_b := canm.Marshall()
	b := append(head, msg_b...)
	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	// Read server's algorithm negotiation message
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}

	// DSA verify server's message
	msg, suc := proto.VerifyServerDSASignature(buf, dsaPubKey)
	if !suc {
		fmt.Println("DSA Verify failed")
		return false
	}

	// Unmarshall server's algorithm negotiation message
	sanm, err := proto.UnmarshallServerNegotiation(msg)
	if err != nil {
		fmt.Println("Unmarshall server negotiation failed")
		return false
	}

	// Do algorithm negotiation
	agreed, err := proto.DoNegotiation(canm, sanm)
	if err != nil {
		fmt.Println("Do negotiation failed")
		return false
	}

	csi.AgreedAlgorithm = agreed
	return true
}