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

func DoProtocolVersionExchange(csi *info.ClientServerInfo, cci *info.ClientClientInfo) bool {

	conn := csi.ServerConn
	dsaPubKey := csi.ServerDSAPubKey

	// create client's protocol version message
	client_pvm := proto.CreateProtocolVersionMessage()
	cci.ClientPVM = client_pvm
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
	sPVM, _, err := client_pvm.UnmarshallAndVerify(msg)

	// store server's protocol version message
	csi.PVM = sPVM

	return err == nil
}

func DoAlgorithmNegotiation(csi *info.ClientServerInfo, cci *info.ClientClientInfo) bool {

	conn := csi.ServerConn
	dsaPubKey := csi.ServerDSAPubKey

	// prepend the message type and cookie
	// SSH_MSG_KEXINIT = 20 (1 byte)
	// cookie = 16 bytes
	cookie := proto.GenerateCookie()

	b := make([]byte, 0)
	b = append(b, util.SSH_MSG_KEXINIT)
	b = append(b, cookie...)

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

	// Send client's algorithm negotiation message
	msg_b := canm.Marshall()
	b = append(b, msg_b...)
	cci.ClientKInitMSG = b

	// Binary Packet Protocol
	binPacket := proto.CreateBinPacket(b, nil)
	b = binPacket.Marshall()

	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	// Read server's algorithm negotiation message
	buf := make([]byte, util.MAX_PACKET_SIZE)
	_, err = conn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}

	binPacket, _  = proto.UnmarshallBinaryPacket(buf)
	payload := binPacket.Payload

	// DSA verify server's message
	msg, suc := proto.VerifyServerDSASignature(payload, dsaPubKey)
	if !suc {
		fmt.Println("DSA Verify failed")
		return false
	}
	csi.KInitMSG = msg
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

func DoServiceRequest(cci *info.ClientClientInfo, csi *info.ClientServerInfo, service string) bool {
	serviceReq := &proto.ServiceRequestMessage{
		MessageType: util.SSH_MSG_SERVICE_REQUEST,
	}
	if (service != "ssh-userauth") && (service != "ssh-connection") {
		fmt.Println("Invalid service")
		return false
	}
	serviceReq.ServiceName = service
	msg_b := serviceReq.Marshall()
	binPacket := proto.CreateBinPacket(msg_b, nil)
	mac, err := proto.ComputeMAC(binPacket, csi.ClientSeqNum, csi.Keys.IntKey_C2S)
	if err != nil {
		fmt.Println("Compute MAC failed")
		return false
	}
	binPacket.MAC = mac
	b := binPacket.Marshall()
	_, err = csi.ServerConn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	csi.ClientSeqNum++

	buf := make([]byte, util.MAX_PACKET_SIZE)
	_, err = csi.ServerConn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}

	binPacket, _ = proto.UnmarshallBinaryPacket(buf)
	suc := proto.VerifyMAC(binPacket, csi.ServerSeqNum, csi.Keys.IntKey_S2C)
	if !suc {
		fmt.Println("MAC verification failed")
		return false
	}

	csi.ServerSeqNum++

	payload := binPacket.Payload
	msg := proto.UnmarshallServiceAccept(payload)
	if msg.MessageType != util.SSH_MSG_SERVICE_ACCEPT {
		fmt.Println("Invalid message type")
		return false
	}

	return msg.ServiceName == service
}