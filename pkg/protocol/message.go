package protocol

import (
	"crypto/dsa"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"bytes"
	"ssh/util"
)

// Message that gets exchanged between client and server upon connection
// e.g. SSH-2.0-OpenSSH_7.9p1
type ProtocolVersionMessage struct {
	Proto           string   // SSH
	ProtoVersion    string   // 2.0
	SoftwareVersion string   // Compatability check
	Comments        []string // Additional info
}

type SignedMessage struct {
	MessageLength uint32
	MessageBytes []byte
	SignatureLength uint32
	Signature    []byte
}

// Message that gets exchanged between client and server upon connection and after the ProtocolVersionMessage
type ClientAlgorithmNegotiationMessage struct {
	Kex_algorithms                          []string
	Server_host_key_algorithms              []string
	Encryption_algorithms_client_to_server  []string
	Mac_algorithms_client_to_server         []string
	Compression_algorithms_client_to_server []string
	Languages_client_to_server              []string
	First_kex_packet_follows                bool
}

type ServerAlgorithmNegotiationMessage struct {
	Kex_algorithms                          []string
	Server_host_key_algorithms              []string
	Encryption_algorithms_server_to_client  []string
	Mac_algorithms_server_to_client         []string
	Compression_algorithms_server_to_client []string
	Languages_server_to_client              []string
	First_kex_packet_follows                bool
}

func CreateClientAlgorithmNegotiationMessage() *ClientAlgorithmNegotiationMessage {
	return &ClientAlgorithmNegotiationMessage{
		Kex_algorithms:                          []string{},
		Server_host_key_algorithms:              []string{},
		Encryption_algorithms_client_to_server:  []string{},
		Mac_algorithms_client_to_server:         []string{},
		Compression_algorithms_client_to_server: []string{},
		Languages_client_to_server:              []string{},
		First_kex_packet_follows:                false,
	}
}

func CreateServerAlgorithmNegotiationMessage() *ServerAlgorithmNegotiationMessage {
	return &ServerAlgorithmNegotiationMessage{
		Kex_algorithms:                          []string{},
		Server_host_key_algorithms:              []string{},
		Encryption_algorithms_server_to_client:  []string{},
		Mac_algorithms_server_to_client:         []string{},
		Compression_algorithms_server_to_client: []string{},
		Languages_server_to_client:              []string{},
		First_kex_packet_follows:                false,
	}
}

// marshalls the message into a byte array
// size of each namelist always precedes the namelist
func (sanm *ServerAlgorithmNegotiationMessage) Marshall() []byte {
	
	buf := new(bytes.Buffer)

	// Kex_algorithms
	// join the strings with a comma
	kex_algorithms := strings.Join(sanm.Kex_algorithms, ",")
	// write the length of the string
	binary.Write(buf, binary.BigEndian, uint32(len(kex_algorithms)))
	// write the string
	binary.Write(buf, binary.BigEndian, []byte(kex_algorithms))

	// Server_host_key_algorithms
	server_host_key_algorithms := strings.Join(sanm.Server_host_key_algorithms, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(server_host_key_algorithms)))
	binary.Write(buf, binary.BigEndian, []byte(server_host_key_algorithms))

	// Encryption_algorithms_server_to_client
	encryption_algorithms_server_to_client := strings.Join(sanm.Encryption_algorithms_server_to_client, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(encryption_algorithms_server_to_client)))
	binary.Write(buf, binary.BigEndian, []byte(encryption_algorithms_server_to_client))

	// Mac_algorithms_server_to_client
	mac_algorithms_server_to_client := strings.Join(sanm.Mac_algorithms_server_to_client, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(mac_algorithms_server_to_client)))
	binary.Write(buf, binary.BigEndian, []byte(mac_algorithms_server_to_client))

	// Compression_algorithms_server_to_client
	compression_algorithms_server_to_client := strings.Join(sanm.Compression_algorithms_server_to_client, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(compression_algorithms_server_to_client)))
	binary.Write(buf, binary.BigEndian, []byte(compression_algorithms_server_to_client))

	// Languages_server_to_client
	languages_server_to_client := strings.Join(sanm.Languages_server_to_client, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(languages_server_to_client)))
	binary.Write(buf, binary.BigEndian, []byte(languages_server_to_client))

	// First_kex_packet_follows
	if sanm.First_kex_packet_follows {
		binary.Write(buf, binary.BigEndian, uint8(1))
	} else {
		binary.Write(buf, binary.BigEndian, uint8(0))
	}

	return buf.Bytes()
}

// unmarshalls the byte array into a message
func UnmarshallServerNegotiation(buf []byte) (*ServerAlgorithmNegotiationMessage, error) {

	sanm := new(ServerAlgorithmNegotiationMessage)

	var curr uint32 = 0

	// first byte is the message type
	if buf[0] != util.SSH_MSG_KEXINIT {
		return nil, errors.New("invalid message type")
	}

	curr += 1

	// next 16 bytes are cookie so ignore them
	curr += 16

	// Kex_algorithms
	kex_len := binary.BigEndian.Uint32(buf[curr:curr+4]) // get the length of the namelist
	kex_algorithms := string(buf[curr+4:curr+kex_len+4]) // get the namelist
	sanm.Kex_algorithms = strings.Split(kex_algorithms, ",") // split the namelist into a slice
	curr += uint32(kex_len) + 4 // update the current position

	// Server_host_key_algorithms
	host_key_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	host_key_algorithms := string(buf[curr+4:curr+host_key_len+4])
	sanm.Server_host_key_algorithms = strings.Split(host_key_algorithms, ",")
	curr += uint32(host_key_len) + 4

	// Encryption_algorithms_server_to_client
	enc_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	enc_algorithms := string(buf[curr+4:curr+enc_len+4])
	sanm.Encryption_algorithms_server_to_client = strings.Split(enc_algorithms, ",")
	curr += uint32(enc_len) + 4

	// Mac_algorithms_server_to_client
	mac_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	mac_algorithms := string(buf[curr+4:curr+mac_len+4])
	sanm.Mac_algorithms_server_to_client = strings.Split(mac_algorithms, ",")
	curr += uint32(mac_len) + 4

	// Compression_algorithms_server_to_client
	compression_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	compression_algorithms := string(buf[curr+4:curr+compression_len+4])
	sanm.Compression_algorithms_server_to_client = strings.Split(compression_algorithms, ",")
	curr += uint32(compression_len) + 4

	// Languages_server_to_client
	languages_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	languages := string(buf[curr+4:curr+languages_len+4])
	sanm.Languages_server_to_client = strings.Split(languages, ",")
	curr += uint32(languages_len) + 4

	// First_kex_packet_follows
	if buf[curr] == 1 {
		sanm.First_kex_packet_follows = true
	} else {
		sanm.First_kex_packet_follows = false
	}

	return sanm, nil
}

// Similar as above
func (canm *ClientAlgorithmNegotiationMessage) Marshall() []byte {
	buf := new(bytes.Buffer)

	// Kex_algorithms
	kex_algorithms := strings.Join(canm.Kex_algorithms, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(kex_algorithms)))
	binary.Write(buf, binary.BigEndian, []byte(kex_algorithms))

	// Server_host_key_algorithms
	server_host_key_algorithms := strings.Join(canm.Server_host_key_algorithms, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(server_host_key_algorithms)))
	binary.Write(buf, binary.BigEndian, []byte(server_host_key_algorithms))

	// Encryption_algorithms_client_to_server
	encryption_algorithms_client_to_server := strings.Join(canm.Encryption_algorithms_client_to_server, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(encryption_algorithms_client_to_server)))
	binary.Write(buf, binary.BigEndian, []byte(encryption_algorithms_client_to_server))

	// Mac_algorithms_client_to_server
	mac_algorithms_client_to_server := strings.Join(canm.Mac_algorithms_client_to_server, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(mac_algorithms_client_to_server)))
	binary.Write(buf, binary.BigEndian, []byte(mac_algorithms_client_to_server))

	// Compression_algorithms_client_to_server
	compression_algorithms_client_to_server := strings.Join(canm.Compression_algorithms_client_to_server, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(compression_algorithms_client_to_server)))
	binary.Write(buf, binary.BigEndian, []byte(compression_algorithms_client_to_server))

	// Languages_client_to_server
	languages_client_to_server := strings.Join(canm.Languages_client_to_server, ",")
	binary.Write(buf, binary.BigEndian, uint32(len(languages_client_to_server)))
	binary.Write(buf, binary.BigEndian, []byte(languages_client_to_server))

	// First_kex_packet_follows
	if canm.First_kex_packet_follows {
		binary.Write(buf, binary.BigEndian, uint8(1))
	} else {
		binary.Write(buf, binary.BigEndian, uint8(0))
	}

	return buf.Bytes()
}

func UnmarshallClientNegotiation(buf []byte) (*ClientAlgorithmNegotiationMessage, uint32, error){

	canm := &ClientAlgorithmNegotiationMessage{}

	var curr uint32 = 0

	// First byte is the message type
	if buf[0] != util.SSH_MSG_KEXINIT {
		return nil, 0, errors.New("invalid message type")
	}

	// Skip the message type
	curr += 1

	// Cookie
	curr += 16

	// Kex_algorithms
	kex_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	kex_algorithms := string(buf[curr+4:curr+kex_len+4])
	canm.Kex_algorithms = strings.Split(kex_algorithms, ",")
	curr += uint32(kex_len) + 4

	// Server_host_key_algorithms
	host_key_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	host_key_algorithms := string(buf[curr+4:curr+host_key_len+4])
	canm.Server_host_key_algorithms = strings.Split(host_key_algorithms, ",")
	curr += uint32(host_key_len) + 4

	// Encryption_algorithms_client_to_server
	enc_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	enc_algorithms := string(buf[curr+4:curr+enc_len+4])
	canm.Encryption_algorithms_client_to_server = strings.Split(enc_algorithms, ",")
	curr += uint32(enc_len) + 4

	// Mac_algorithms_client_to_server
	mac_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	mac_algorithms := string(buf[curr+4:curr+mac_len+4])
	canm.Mac_algorithms_client_to_server = strings.Split(mac_algorithms, ",")
	curr += uint32(mac_len) + 4

	// Compression_algorithms_client_to_server
	compression_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	compression_algorithms := string(buf[curr+4:curr+compression_len+4])
	canm.Compression_algorithms_client_to_server = strings.Split(compression_algorithms, ",")
	curr += uint32(compression_len) + 4

	// Languages_client_to_server
	languages_len := binary.BigEndian.Uint32(buf[curr:curr+4])
	languages := string(buf[curr+4:curr+languages_len+4])
	canm.Languages_client_to_server = strings.Split(languages, ",")
	curr += uint32(languages_len) + 4

	// First_kex_packet_follows
	if buf[curr] == 1 {
		canm.First_kex_packet_follows = true
	} else {
		canm.First_kex_packet_follows = false
	}

	return canm, curr, nil
}

func SignServerDSA(msg_bytes []byte, privKey *dsa.PrivateKey) []byte {
	ret := &SignedMessage{}
	ret.MessageLength = uint32(len(msg_bytes))
	ret.MessageBytes = msg_bytes
	sig, err := DSASign(msg_bytes, privKey)
	if err != nil {
		fmt.Println("DSA Sign failed:", err.Error())
		return nil
	}
	ret.SignatureLength = uint32(len(sig))
	ret.Signature = sig
	return ret.Marshall()
}

// 4 bytes for message length
// + message length bytes
// + 4 bytes for signature length
// + signature length bytes
func (spvm *SignedMessage) Marshall() []byte {
	data := make([]byte, 4+spvm.MessageLength+4+spvm.SignatureLength)
	binary.BigEndian.PutUint32(data, spvm.MessageLength)
	copy(data[4:], spvm.MessageBytes)
	binary.BigEndian.PutUint32(data[4+spvm.MessageLength:], spvm.SignatureLength)
	copy(data[4+spvm.MessageLength+4:], spvm.Signature)
	return data
}

func VerifyServerDSASignature(buf []byte, pubKey *dsa.PublicKey) ([]byte, bool) {
	// read the first 4 bytes
	msg_len := binary.BigEndian.Uint32(buf[:4])
	// read the next msg_len bytes
	msg_bytes := buf[4:msg_len+4]
	// read the next 4 bytes
	sig_len := binary.BigEndian.Uint32(buf[msg_len+4:msg_len+8])
	// read the next sig_len bytes
	sig_bytes := buf[msg_len+8:msg_len+8+sig_len]
	// verify the signature
	_, err := DSAVerify(msg_bytes, pubKey, sig_bytes)
	if err != nil {
		fmt.Println("DSA Verify failed:", err.Error())
		return nil, false
	}
	return msg_bytes, true
}

func CreateProtocolVersionMessage() *ProtocolVersionMessage {
	// Hardcoded for now
	return &ProtocolVersionMessage{
		Proto:           "SSH",
		ProtoVersion:    "2.0",
		SoftwareVersion: "bigdawsSSH",
		Comments:        []string{},
	}
}

// Construct a string representation of the protocol version message
// Ending with <CR><LF> as per RFC 4253 section 4.2
func (pvm *ProtocolVersionMessage) ToString() string {
	if len(pvm.Comments) == 0 {
		return fmt.Sprintf("%s-%s-%s\r\n", pvm.Proto, pvm.ProtoVersion, pvm.SoftwareVersion)
	}
	return fmt.Sprintf("%s-%s-%s %s\r\n", pvm.Proto, pvm.ProtoVersion, pvm.SoftwareVersion, strings.Join(pvm.Comments, " "))
}

// Marshall the protocol version message into a byte array
func (pvm *ProtocolVersionMessage) Marshall() []byte {
	// 255 is the max length of a protocol version message
	data := make([]byte, 255)
	pvm_str := pvm.ToString()
	pvm_str_sz := len(pvm_str)
	// copy the size first
	binary.BigEndian.PutUint32(data, uint32(pvm_str_sz))
	// copy the string
	copy(data[4:], pvm_str)
	return data
}

// Function that verifies the protocol version message has the following format
// SSH-Version-SofwareVersion<CR><LF> or SSH-Version-SofwareVersion comments<CR><LF>
func (pvm *ProtocolVersionMessage) UnmarshallAndVerify(data []byte) (*ProtocolVersionMessage, []string, error) {
	// Read the size
	sz := binary.BigEndian.Uint32(data[:4])
	// Read the string
	s := string(data[4 : sz+4])
	// Verify that the string ends with <CR><LF>
	if s[len(s)-1] != '\n' || s[len(s)-2] != '\r' {
		return nil, nil, errors.New("error: protocol version message does not end with <CR><LF>")
	}
	// Split the string into the first half and second half
	split_one := strings.Split(s, " ")
	var (
		proto           string
		protoVersion    string
		softwareVersion string
		comments        []string
	)

	// no comments
	if len(split_one) < 2 {
		comments = []string{}
	} else {
		last := split_one[len(split_one)-1]
		// remove <CR><LF>
		split_one[len(split_one)-1] = last[:len(last)-2]
		comments = split_one[1:]
	}

	split := strings.Split(split_one[0], "-")
	proto = split[0]
	protoVersion = split[1]

	if len(split_one) < 2 {
		// rm <CR><LF>
		softwareVersion = split[2][:len(split[2])-2]
	} else {
		softwareVersion = split[2]
	}

	if proto != pvm.Proto {
		return nil, nil, errors.New("error: protocol version message does not start with 'SSH'")
	}

	if protoVersion != pvm.ProtoVersion {
		return nil, nil, errors.New("error: protocol version does not match")
	}

	if softwareVersion != pvm.SoftwareVersion {
		return nil, nil, errors.New("error: software version does not match")
	}

	protoVM := &ProtocolVersionMessage{
		Proto:           proto,
		ProtoVersion:    protoVersion,
		SoftwareVersion: softwareVersion,
		Comments:        comments,
	}

	return protoVM, comments, nil
}
