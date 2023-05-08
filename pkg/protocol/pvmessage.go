package protocol

import (
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
