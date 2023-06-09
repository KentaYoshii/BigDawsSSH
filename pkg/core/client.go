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
	binPacket := proto.CreateBinPacket(b, 16)
	b = binPacket.Marshall()

	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

retry:
	// Read server's algorithm negotiation message
	buf := make([]byte, util.MAX_PACKET_SIZE)
	_, err = conn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}

	binPacket, _ = proto.UnmarshallBinaryPacket(buf)
	payload := binPacket.Payload

	// DSA verify server's message
	msg, suc := proto.VerifyServerDSASignature(payload, dsaPubKey)
	if !suc {
		fmt.Println("DSA Verify failed")
		return false
	}

	m_type := msg[0]
	if m_type == util.SSH_MSG_IGNORE || m_type == util.SSH_MSG_DEBUG {
		goto retry
	} else if m_type == util.SSH_MSG_DISCONNECT {
		fmt.Println("Received disconnec message")
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

	enc_algo := csi.AgreedAlgorithm.Encryption_algorithm
	mac_algo := csi.AgreedAlgorithm.Mac_algorithm

	serviceReq := &proto.ServiceRequestMessage{
		MessageType: util.SSH_MSG_SERVICE_REQUEST,
	}
	if (service != "ssh-userauth") && (service != "ssh-connection") {
		fmt.Println("Invalid service")
		return false
	}
	serviceReq.ServiceName = service
	msg_b := serviceReq.Marshall()
	binPacket := proto.CreateBinPacket(msg_b, uint32(csi.BLK_SIZE))
	encryptedBinaryPacket, err := proto.EncryptAndMac(binPacket, csi.Keys.EncKey_C2S,
		csi.Keys.IntKey_C2S, csi.Keys.IV_C2S, csi.ClientSeqNum, enc_algo, mac_algo)
	if err != nil {
		fmt.Println("Encrypt and mac failed")
		return false
	}
	b := encryptedBinaryPacket.Marshall()
	_, err = csi.ServerConn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	csi.ClientSeqNum++

retry:
	buf := make([]byte, util.MAX_PACKET_SIZE)
	_, err = csi.ServerConn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}
	encryptedPacket, _ := proto.UnmarshallEncryptedBinaryPacket(buf)
	binPacket, err = proto.DecryptAndVerify(encryptedPacket, csi.Keys.EncKey_S2C,
		csi.Keys.IntKey_S2C, csi.Keys.IV_S2C, csi.ServerSeqNum, enc_algo, mac_algo)
	if err != nil {
		fmt.Println("Decrypt and verify failed")
		return false
	}

	payload := binPacket.Payload
	m_type := payload[0]
	if m_type == util.SSH_MSG_IGNORE || m_type == util.SSH_MSG_DEBUG {
		goto retry
	} else if m_type == util.SSH_MSG_DISCONNECT {
		fmt.Println("Received disconnec message")
		return false
	}

	csi.ServerSeqNum++

	msg := proto.UnmarshallServiceAccept(payload)
	if msg.MessageType != util.SSH_MSG_SERVICE_ACCEPT {
		fmt.Println("Invalid message type")
		return false
	}

	return msg.ServiceName == service
}

func QueryServerPKAuth(cci *info.ClientClientInfo, csi *info.ClientServerInfo) bool {
	userauthRequest := &proto.PK_UserAuthRequest{
		MessageType: util.SSH_MSG_USERAUTH_REQUEST,
		Username:    cci.Username,
		ServiceName: "ssh-connection",
		Method:      "publickey",
		Direct:      false,
		PKAlgorithm: "ssh-rsa",
		PKBlob:      proto.PublicKeyToBytes(cci.RSAPublicKey),
	}

	msg_b := userauthRequest.Marshall()
	binPacket := proto.CreateBinPacket(msg_b, uint32(csi.BLK_SIZE))
	encryptedPacket, err := proto.EncryptAndMac(binPacket, csi.Keys.EncKey_C2S,
		csi.Keys.IntKey_C2S, csi.Keys.IV_C2S, csi.ClientSeqNum,
		csi.AgreedAlgorithm.Encryption_algorithm, csi.AgreedAlgorithm.Mac_algorithm)
	if err != nil {
		fmt.Println("Encrypt and mac failed")
		return false
	}
	b := encryptedPacket.Marshall()
	_, err = csi.ServerConn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	csi.ClientSeqNum++

	// read server's response
	buf := make([]byte, util.MAX_PACKET_SIZE)
	_, err = csi.ServerConn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}
	encryptedPacket, _ = proto.UnmarshallEncryptedBinaryPacket(buf)
	binPacket, err = proto.DecryptAndVerify(encryptedPacket, csi.Keys.EncKey_S2C,
		csi.Keys.IntKey_S2C, csi.Keys.IV_S2C, csi.ServerSeqNum,
		csi.AgreedAlgorithm.Encryption_algorithm, csi.AgreedAlgorithm.Mac_algorithm)
	if err != nil {
		fmt.Println("Decrypt and verify failed")
		return false
	}

	payload := binPacket.Payload
	m_type := payload[0]
	if m_type != util.SSH_MSG_USERAUTH_PK_OK {
		fmt.Println("Server does not accept public key authentication")
		return false
	}

	csi.ServerSeqNum++

	return true
}

func DoPWAuth(cci *info.ClientClientInfo, csi *info.ClientServerInfo) bool {
	pw_req := &proto.PW_UserAuthRequest{
		MessageType: util.SSH_MSG_USERAUTH_REQUEST,
		Username:    cci.Username,
		ServiceName: "ssh-connection",
		Method:      "password",
		Direct:      false,
		Password:    cci.Password,
	}

	msg_b := pw_req.Marshall()
	binPacket := proto.CreateBinPacket(msg_b, uint32(csi.BLK_SIZE))
	encryptedPacket, err := proto.EncryptAndMac(binPacket, csi.Keys.EncKey_C2S,
		csi.Keys.IntKey_C2S, csi.Keys.IV_C2S, csi.ClientSeqNum,
		csi.AgreedAlgorithm.Encryption_algorithm, csi.AgreedAlgorithm.Mac_algorithm)
	if err != nil {
		fmt.Println("Encrypt and mac failed")
		return false
	}
	b := encryptedPacket.Marshall()
	_, err = csi.ServerConn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	csi.ClientSeqNum++

	// read server's response
	buf := make([]byte, util.MAX_PACKET_SIZE)
	_, err = csi.ServerConn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}
	encryptedPacket, _ = proto.UnmarshallEncryptedBinaryPacket(buf)
	binPacket, err = proto.DecryptAndVerify(encryptedPacket, csi.Keys.EncKey_S2C,
		csi.Keys.IntKey_S2C, csi.Keys.IV_S2C, csi.ServerSeqNum,
		csi.AgreedAlgorithm.Encryption_algorithm, csi.AgreedAlgorithm.Mac_algorithm)
	if err != nil {
		fmt.Println("Decrypt and verify failed")
		return false
	}

	payload := binPacket.Payload
	m_type := payload[0]

	return m_type == util.SSH_MSG_USERAUTH_SUCCESS
}

func DoPKAuth(cci *info.ClientClientInfo, csi *info.ClientServerInfo, sig []byte) bool {
	// send signature
	userauthRequest := &proto.PK_UserAuthRequestWithSignature{
		MessageType: util.SSH_MSG_USERAUTH_REQUEST,
		Username:    cci.Username,
		ServiceName: "ssh-connection",
		Method:      "publickey",
		Direct:      true,
		PKAlgorithm: "ssh-rsa",
		PKBlob:      cci.RSAPublicKeyBytes,
		Signature:   sig,
	}

	msg_b := userauthRequest.Marshall()
	binPacket := proto.CreateBinPacket(msg_b, uint32(csi.BLK_SIZE))
	encryptedPacket, err := proto.EncryptAndMac(binPacket, csi.Keys.EncKey_C2S,
		csi.Keys.IntKey_C2S, csi.Keys.IV_C2S, csi.ClientSeqNum,
		csi.AgreedAlgorithm.Encryption_algorithm, csi.AgreedAlgorithm.Mac_algorithm)
	if err != nil {
		fmt.Println("Encrypt and mac failed")
		return false
	}
	b := encryptedPacket.Marshall()
	_, err = csi.ServerConn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	csi.ClientSeqNum++

	// read server's response
	buf := make([]byte, util.MAX_PACKET_SIZE)
	_, err = csi.ServerConn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}
	encryptedPacket, _ = proto.UnmarshallEncryptedBinaryPacket(buf)
	binPacket, err = proto.DecryptAndVerify(encryptedPacket, csi.Keys.EncKey_S2C,
		csi.Keys.IntKey_S2C, csi.Keys.IV_S2C, csi.ServerSeqNum,
		csi.AgreedAlgorithm.Encryption_algorithm, csi.AgreedAlgorithm.Mac_algorithm)
	if err != nil {
		fmt.Println("Decrypt and verify failed")
		return false
	}

	payload := binPacket.Payload
	m_type := payload[0]
	if m_type != util.SSH_MSG_USERAUTH_SUCCESS {
		fmt.Println("authentication failed")
		return false
	}

	csi.ServerSeqNum++

	return true
}
