package protocol

import (
	"net"
	"fmt"
	dh "github.com/monnand/dhkx"
	"ssh/util"
	"encoding/binary"
	"bytes"
	"errors"
)

/*
8.1.  diffie-hellman-group1-sha1

   The "diffie-hellman-group1-sha1" method specifies the Diffie-Hellman
   key exchange with SHA-1 as HASH, and Oakley Group 2 [RFC2409] (1024-
   bit MODP Group).  This method MUST be supported for interoperability
   as all of the known implementations currently support it.  Note that
   this method is named using the phrase "group1", even though it
   specifies the use of Oakley Group 2.

8.2.  diffie-hellman-group14-sha1

   The "diffie-hellman-group14-sha1" method specifies a Diffie-Hellman
   key exchange with SHA-1 as HASH and Oakley Group 14 [RFC3526] (2048-
   bit MODP Group), and it MUST also be supported.
*/

type ClientServerKEXInit struct {
	MessageType byte
	ClientPublicKey *dh.DHKey
}

func (c *ClientServerKEXInit) Marshall() []byte {
	buf := new(bytes.Buffer)
	p_bytes := c.ClientPublicKey.Bytes()
	sz := len(p_bytes)
	// 1 byte for message type
	buf.WriteByte(c.MessageType)
	// 4 bytes for client's public key length
	binary.Write(buf, binary.BigEndian, uint32(sz))
	// client's public key
	buf.Write(p_bytes)
	return buf.Bytes()
}

func UnmarshallInitMessage(buf []byte) (*ClientServerKEXInit, error) {
	c := new(ClientServerKEXInit)
	// 1 byte for message type
	c.MessageType = buf[0]
	if c.MessageType != util.SSH_MSG_KEXDH_INIT {
		return nil, errors.New("wrong message type from client")
	}
	// 4 bytes for client's public key length
	sz := binary.BigEndian.Uint32(buf[1:5])
	// client's public key
	pub_key_b := buf[5:5+sz]
	cli_pub_key := dh.NewPublicKey(pub_key_b)
	c.ClientPublicKey = cli_pub_key
	return c, nil
}

type KeyExchange func(*net.TCPConn) bool

func Do_KEX_Client(algorithm string) KeyExchange {
	switch algorithm {
	case "diffie-hellman-group1-sha1":
		return DH1_KEX_Client
	case "diffie-hellman-group14-sha1":
		return Do_DH14_KEX
	default:
		return nil
	}
}

func Do_KEX_Server(algorithm string) KeyExchange {
	switch algorithm {
	case "diffie-hellman-group1-sha1":
		return DH1_KEX_Server
	case "diffie-hellman-group14-sha1":
		return Do_DH14_KEX
	default:
		return nil
	}
}

func GetKeys(group int) (pubKey *dh.DHKey, priKey *dh.DHKey) {
	// generate DH parameters
	g, err := dh.GetGroup(group)
	if err != nil {
		fmt.Println("Error generating DH parameters:", err.Error())
		return nil, nil
	}
	// generate DH key pair
	priKey, err = g.GeneratePrivateKey(nil) // a in g^a mod p
	if err != nil {
		fmt.Println("Error generating DH key pair:", err.Error())
		return nil, nil
	}
	// Get the public key from the private key.
	pub := priKey.Bytes()
	pubKey = dh.NewPublicKey(pub) // g^a mod p
	return pubKey, priKey
}

func DH1_KEX_Server(conn *net.TCPConn) bool {
	// read client's public key
	buf := make([]byte, 4096)
	_, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Read from client failed:", err.Error())
		return false
	}
	// unmarshall client's public key
	initMsg, err := UnmarshallInitMessage(buf)
	if err != nil {
		fmt.Println("Unmarshall client's public key failed:", err.Error())
		return false
	}
	return true
}

// 1. Client generates a random number x (1 < x < q) and computes
// e = g^x mod p.  C sends e to Server
func DH1_KEX_Client(conn *net.TCPConn) bool {
	pubKey, priKey := GetKeys(2)
	if pubKey == nil || priKey == nil {
		return false
	}
	// send my public key over
	initMsg := &ClientServerKEXInit{
		MessageType: util.SSH_MSG_KEXDH_INIT,
		ClientPublicKey: pubKey,
	}
	b := initMsg.Marshall()
	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	return true
}

func Do_DH14_KEX(conn *net.TCPConn) bool {
	return true
}

