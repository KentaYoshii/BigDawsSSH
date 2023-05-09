package protocol

import (
	"crypto/dsa"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Message that gets exchanged between client and server upon connection
// e.g. SSH-2.0-OpenSSH_7.9p1
type ProtocolVersionMessage struct {
	Proto           string   // SSH
	ProtoVersion    string   // 2.0
	SoftwareVersion string   // Compatability check
	Comments        []string // Additional info
}

type SignedProtocolVersionMessage struct {
	MessageLength uint32
	MessageBytes []byte
	SignatureLength uint32
	Signature    []byte
}

func SignServerDSA(msg_bytes []byte, privKey *dsa.PrivateKey) []byte {
	ret := &SignedProtocolVersionMessage{}
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
func (spvm *SignedProtocolVersionMessage) Marshall() []byte {
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
func (pvm *ProtocolVersionMessage) UnmarshallAndVerify(data []byte) ([]string, error) {
	// Read the size
	sz := binary.BigEndian.Uint32(data[:4])
	// Read the string
	s := string(data[4 : sz+4])
	// Verify that the string ends with <CR><LF>
	if s[len(s)-1] != '\n' || s[len(s)-2] != '\r' {
		return nil, errors.New("error: protocol version message does not end with <CR><LF>")
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
		return nil, errors.New("error: protocol version message does not start with 'SSH'")
	}

	if protoVersion != pvm.ProtoVersion {
		return nil, errors.New("error: protocol version does not match")
	}

	if softwareVersion != pvm.SoftwareVersion {
		return nil, errors.New("error: software version does not match")
	}

	return comments, nil
}
