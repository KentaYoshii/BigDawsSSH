package protocol

import (
	"bytes"
	"encoding/binary"
)

type PK_UserAuthRequest struct {
	MessageType uint8
	Username    string
	ServiceName string
	Method      string
	Direct      bool
	PKAlgorithm string
	PKBlob      string
}

type PK_UserAuthOk struct {
	MessageType uint8
	PKAlgorithm string
	PKBlob      string
}

type UserAuthFailure struct {
	MessageType uint8
	AuthMethods string
	PartialSuccess bool
}

// ------------------ PK_UserAuthRequest ------------------

func (p *PK_UserAuthRequest) Marshall() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, p.MessageType)
	binary.Write(buf, binary.BigEndian, uint32(len(p.Username)))
	buf.Write([]byte(p.Username))
	binary.Write(buf, binary.BigEndian, uint32(len(p.ServiceName)))
	buf.Write([]byte(p.ServiceName))
	binary.Write(buf, binary.BigEndian, uint32(len(p.Method)))
	buf.Write([]byte(p.Method))
	binary.Write(buf, binary.BigEndian, p.Direct)
	binary.Write(buf, binary.BigEndian, uint32(len(p.PKAlgorithm)))
	buf.Write([]byte(p.PKAlgorithm))
	binary.Write(buf, binary.BigEndian, uint32(len(p.PKBlob)))
	buf.Write([]byte(p.PKBlob))
	return buf.Bytes()
}

func UnmarshallPK_UserAuthRequest(b []byte) (*PK_UserAuthRequest, error) {
	curr := 0
	p := &PK_UserAuthRequest{}
	p.MessageType = uint8(b[curr])
	curr += 1
	username_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	p.Username = string(b[curr : curr+int(username_len)])
	curr += int(username_len)
	service_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	p.ServiceName = string(b[curr : curr+int(service_len)])
	curr += int(service_len)
	method_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	p.Method = string(b[curr : curr+int(method_len)])
	curr += int(method_len)
	p.Direct = b[curr] == 1
	curr += 1
	pk_alg_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	p.PKAlgorithm = string(b[curr : curr+int(pk_alg_len)])
	curr += int(pk_alg_len)
	pk_blob_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	p.PKBlob = string(b[curr : curr+int(pk_blob_len)])
	return p, nil
}

// ------------------ PK_UserAuthOk ------------------

func (p *PK_UserAuthOk) Marshall() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, p.MessageType)
	binary.Write(buf, binary.BigEndian, uint32(len(p.PKAlgorithm)))
	buf.Write([]byte(p.PKAlgorithm))
	binary.Write(buf, binary.BigEndian, uint32(len(p.PKBlob)))
	buf.Write([]byte(p.PKBlob))
	return buf.Bytes()
}

func UnmarshallPK_UserAuthOk(b []byte) (*PK_UserAuthOk, error) {
	curr := 0
	p := &PK_UserAuthOk{}
	p.MessageType = uint8(b[curr])
	curr += 1
	pk_alg_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	p.PKAlgorithm = string(b[curr : curr+int(pk_alg_len)])
	curr += int(pk_alg_len)
	pk_blob_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	p.PKBlob = string(b[curr : curr+int(pk_blob_len)])
	return p, nil
}

// ------------------ UserAuthFailure ------------------