package protocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"ssh/util"
	"crypto/rsa"
	"crypto"
	"crypto/rand"
)


type PW_UserAuthRequest struct {
	MessageType uint8
	Username    string
	ServiceName string
	Method      string
	Direct      bool
	Password    string
}
type PK_UserAuthRequest struct {
	MessageType uint8
	Username    string
	ServiceName string
	Method      string
	Direct      bool
	PKAlgorithm string
	PKBlob      []byte
}

type PK_UserAuthRequestWithSignature struct {
	MessageType uint8
	Username	string
	ServiceName string
	Method		string
	Direct		bool
	PKAlgorithm string
	PKBlob		[]byte
	Signature	[]byte
}

type PK_UserAuthOk struct {
	MessageType uint8
	PKAlgorithm string
	PKBlob      []byte
}

type UserAuthFailure struct {
	MessageType uint8
	AuthMethods string
	PartialSuccess bool
}

type UserAuthSuccess struct {
	MessageType uint8
}

// ------------------ PW_UserAuthRequest ------------------
func (p *PW_UserAuthRequest) Marshall() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, p.MessageType)
	binary.Write(buf, binary.BigEndian, uint32(len(p.Username)))
	buf.Write([]byte(p.Username))
	binary.Write(buf, binary.BigEndian, uint32(len(p.ServiceName)))
	buf.Write([]byte(p.ServiceName))
	binary.Write(buf, binary.BigEndian, uint32(len(p.Method)))
	buf.Write([]byte(p.Method))
	binary.Write(buf, binary.BigEndian, p.Direct)
	binary.Write(buf, binary.BigEndian, uint32(len(p.Password)))
	buf.Write([]byte(p.Password))
	return buf.Bytes()
}

func UnmarshallPW_UserAuthRequest(b []byte) (*PW_UserAuthRequest, error) {
	p := new(PW_UserAuthRequest)
	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.BigEndian, &p.MessageType)
	var len uint32
	binary.Read(buf, binary.BigEndian, &len)
	p.Username = string(buf.Next(int(len)))
	binary.Read(buf, binary.BigEndian, &len)
	p.ServiceName = string(buf.Next(int(len)))
	binary.Read(buf, binary.BigEndian, &len)
	p.Method = string(buf.Next(int(len)))
	binary.Read(buf, binary.BigEndian, &p.Direct)
	binary.Read(buf, binary.BigEndian, &len)
	p.Password = string(buf.Next(int(len)))
	return p, nil
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
	p.PKBlob = b[curr : curr+int(pk_blob_len)]
	return p, nil
}

func (pS *PK_UserAuthRequestWithSignature) Marshall() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, pS.MessageType)
	binary.Write(buf, binary.BigEndian, uint32(len(pS.Username)))
	buf.Write([]byte(pS.Username))
	binary.Write(buf, binary.BigEndian, uint32(len(pS.ServiceName)))
	buf.Write([]byte(pS.ServiceName))
	binary.Write(buf, binary.BigEndian, uint32(len(pS.Method)))
	buf.Write([]byte(pS.Method))
	binary.Write(buf, binary.BigEndian, pS.Direct)
	binary.Write(buf, binary.BigEndian, uint32(len(pS.PKAlgorithm)))
	buf.Write([]byte(pS.PKAlgorithm))
	binary.Write(buf, binary.BigEndian, uint32(len(pS.PKBlob)))
	buf.Write([]byte(pS.PKBlob))
	binary.Write(buf, binary.BigEndian, uint32(len(pS.Signature)))
	buf.Write(pS.Signature)
	return buf.Bytes()
}

func UnmarshallPK_UserAuthRequestWithSignature(b []byte) (*PK_UserAuthRequestWithSignature, error) {
	curr := 0
	p := &PK_UserAuthRequestWithSignature{}
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
	p.PKBlob = b[curr : curr+int(pk_blob_len)]
	curr += int(pk_blob_len)
	signature_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	p.Signature = b[curr : curr+int(signature_len)]
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
	p.PKBlob = b[curr : curr+int(pk_blob_len)]
	return p, nil
}

// ------------------ UserAuthFailure ------------------


// ------------------ UserAuthSuccess ------------------
func (p *UserAuthSuccess) Marshall() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, p.MessageType)
	return buf.Bytes()
}

func UnmarshallUserAuthSuccess(b []byte) (*UserAuthSuccess, error) {
	p := &UserAuthSuccess{}
	p.MessageType = uint8(b[0])
	return p, nil
}

// ------------------- PK Signature --------------------
/*
The value of 'signature' is a signature by the corresponding private
   key over the following data, in the following order:

      string    session identifier
      byte      SSH_MSG_USERAUTH_REQUEST
      string    user name
      string    service name
      string    "publickey"
      boolean   TRUE
      string    public key algorithm name
      string    public key to be used for authentication
*/
func ComputePKSignature(session []byte, username, service, algo string, pubkey []byte, privateKey *rsa.PrivateKey) []byte {
	buf := new(bytes.Buffer)
	buf.Write(session)
	buf.WriteByte(util.SSH_MSG_USERAUTH_REQUEST)
	buf.Write([]byte(username))
	buf.Write([]byte(service))
	buf.Write([]byte("publickey"))
	buf.WriteByte(1)
	buf.Write([]byte(algo))
	buf.Write(pubkey)

	hash := sha256.New()
	hash.Write(buf.Bytes())
	hashSum := hash.Sum(nil)
	signature, _ := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashSum, nil)
	return signature
}

func VerifyPKSignature(session []byte, username, service, algo string, pubkey []byte, signature []byte, publicKey *rsa.PublicKey) bool {
	buf := new(bytes.Buffer)
	buf.Write(session)
	buf.WriteByte(util.SSH_MSG_USERAUTH_REQUEST)
	buf.Write([]byte(username))
	buf.Write([]byte(service))
	buf.Write([]byte("publickey"))
	buf.WriteByte(1)
	buf.Write([]byte(algo))
	buf.Write(pubkey)

	hash := sha256.New()
	hash.Write(buf.Bytes())
	hashSum := hash.Sum(nil)

	return rsa.VerifyPSS(publicKey, crypto.SHA256, hashSum, signature, nil) == nil
}