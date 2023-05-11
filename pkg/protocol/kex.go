package protocol

import (
	"bytes"
	"crypto/dsa"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"ssh/util"

	dh "github.com/monnand/dhkx"
)

// ---------------------- KEX Algorithms from RFC 4253 ----------------------

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

// --------------------------------------------------------------------------

type NewKeys struct {
	IV_C2S     []byte
	IV_S2C     []byte
	EncKey_C2S []byte
	EncKey_S2C []byte
	IntKey_C2S []byte
	IntKey_S2C []byte
}

// Generic Hanlder function for Server DH KEX
type KeyExchangeServer func(
	*net.TCPConn, int, *ProtocolVersionMessage, *ProtocolVersionMessage,
	[]byte, []byte, *dsa.PublicKey, *dsa.PrivateKey) (*dh.DHKey, []byte, bool)

// Generic Hanlder function for Client DH KEX
type KeyExchangeClient func(
	*net.TCPConn, int, *ProtocolVersionMessage, *ProtocolVersionMessage,
	[]byte, []byte, *dsa.PublicKey) (*dh.DHKey, []byte, bool)

// Client -> Server KEX Init
type ClientServerKEXInit struct {
	MessageType     byte
	ClientPublicKey *dh.DHKey
}

// Server -> Client KEX Reply
type ServerClientKEXReply struct {
	MessageType     byte
	ServerHostKey   *dsa.PublicKey
	ServerPublicKey *dh.DHKey
	Signature       []byte
}

type NewKeysMessage struct {
	MessageType byte
}

// Function that marshalls the reply struct into a byte array
func (c *ServerClientKEXReply) Marshall() []byte {
	buf := new(bytes.Buffer)
	// 1 byte for message type
	buf.WriteByte(c.MessageType)

	// --- Server Host Key ---
	hk_bytes := c.ServerHostKey.Y.Bytes()
	hk_sz := len(hk_bytes)
	// 4 bytes for server host key length
	binary.Write(buf, binary.BigEndian, uint32(hk_sz))
	// server host key
	buf.Write(hk_bytes)

	// --- Public DH key ---
	p_bytes := c.ServerPublicKey.Bytes()
	sz := len(p_bytes)
	// 4 bytes for server's public key length
	binary.Write(buf, binary.BigEndian, uint32(sz))
	// server's public key
	buf.Write(p_bytes)

	// --- Signature ---
	sig_sz := len(c.Signature)
	// 4 bytes for signature length
	binary.Write(buf, binary.BigEndian, uint32(sig_sz))
	// signature
	buf.Write(c.Signature)

	return buf.Bytes()
}

// Function that unmarshalls the reply byte array into a struct
func UnmarshallReplyMessage(buf []byte) (*ServerClientKEXReply, error) {
	c := &ServerClientKEXReply{}
	var curr uint32 = 0
	// 1 byte for message type
	c.MessageType = buf[0]
	if c.MessageType != util.SSH_MSG_KEXDH_REPLY {
		return nil, errors.New("wrong message type from server")
	}
	curr += 1
	// 4 bytes for server host key length
	hk_sz := binary.BigEndian.Uint32(buf[curr : curr+4])
	curr += 4
	// server host key
	hk_bytes := buf[curr : curr+hk_sz]
	c.ServerHostKey = new(dsa.PublicKey)
	c.ServerHostKey.Y = new(big.Int)
	c.ServerHostKey.Y.SetBytes(hk_bytes)
	curr += hk_sz

	// 4 bytes for server's public key length
	p_sz := binary.BigEndian.Uint32(buf[curr : curr+4])
	curr += 4
	// server's public key
	p_bytes := buf[curr : curr+p_sz]
	s_pub_key := dh.NewPublicKey(p_bytes)
	c.ServerPublicKey = s_pub_key
	curr += p_sz

	// 4 bytes for signature length
	sig_sz := binary.BigEndian.Uint32(buf[curr : curr+4])
	curr += 4
	// signature
	c.Signature = buf[curr : curr+sig_sz]

	return c, nil
}

// Function that marshalls the init struct into a byte array
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

// Function that unmarshalls the init byte array into a struct
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
	pub_key_b := buf[5 : 5+sz]
	cli_pub_key := dh.NewPublicKey(pub_key_b)
	c.ClientPublicKey = cli_pub_key
	return c, nil
}

func Do_KEX_Client(algorithm string) KeyExchangeClient {
	switch algorithm {
	case "diffie-hellman-group1-sha1":
		return DH_KEX_Client
	case "diffie-hellman-group14-sha1":
		return DH_KEX_Client
	default:
		return nil
	}
}

// Function that returns a DH group based on the algorithm
func GetDHGroup(algorithm string) int {
	switch algorithm {
	case "diffie-hellman-group1-sha1":
		return 2 // Oakley Group 2
	case "diffie-hellman-group14-sha1":
		return 14 // Oakley Group 14
	default:
		return -1
	}
}

// Function that returns a handler function based on the algorithm agreed upon
func Do_KEX_Server(algorithm string) KeyExchangeServer {
	switch algorithm {
	case "diffie-hellman-group1-sha1":
		return DH_KEX_Server
	case "diffie-hellman-group14-sha1":
		return DH_KEX_Server
	default:
		return nil
	}
}

// Given a DH group, generate the public and private keys
// Returns the public key, private key and the DH group
func GetKeys(group int) (pubKey *dh.DHKey, priKey *dh.DHKey, g *dh.DHGroup) {
	g, err := dh.GetGroup(group)
	if err != nil {
		fmt.Println("Error generating DH parameters:", err.Error())
		return nil, nil, nil
	}
	// generate DH key pair
	priKey, err = g.GeneratePrivateKey(nil) // a in g^a mod p
	if err != nil {
		fmt.Println("Error generating DH key pair:", err.Error())
		return nil, nil, nil
	}
	// Get the public key from the private key.
	pub := priKey.Bytes()
	pubKey = dh.NewPublicKey(pub) // g^a mod p
	return pubKey, priKey, g
}

// Function that performs the Diffie-Hellman key exchange on the server side
func DH_KEX_Server(conn *net.TCPConn, group int,
	sPVM *ProtocolVersionMessage, cPVM *ProtocolVersionMessage,
	sKInit []byte, cKInit []byte,
	hPubKey *dsa.PublicKey, hPriKey *dsa.PrivateKey) (*dh.DHKey, []byte, bool) {

	// Step 1 - Receive client's public key
	buf := make([]byte, util.MAX_PACKET_SIZE)
	_, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Read from client failed:", err.Error())
		return nil, nil, false
	}

	binPacket, _ := UnmarshallBinaryPacket(buf)
	buf = binPacket.Payload

	initMsg, err := UnmarshallInitMessage(buf)
	if err != nil {
		fmt.Println("Unmarshall client's public key failed:", err.Error())
		return nil, nil, false
	}

	e := initMsg.ClientPublicKey

	// Step 2
	/*
			  S generates a random number y (0 < y < q) and computes
		      f = g^y mod p.  S receives e.  It computes K = e^y mod p,
		      H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
		      (these elements are encoded according to their types; see below),
		      and signature s on H with its private host key.  S sends
		      (K_S || f || s) to C.  The signing operation may involve a
		      second hashing operation.
	*/

	f, y, g := GetKeys(group)
	if f == nil || y == nil {
		return nil, nil, false
	}

	// Compute the key
	k, err := g.ComputeKey(e, y) // k = e^y mod p
	if err != nil {
		fmt.Println("Compute key failed:", err.Error())
		return nil, nil, false
	}

	i_c := cKInit
	i_s := sKInit
	k_s := hPubKey.Y.Bytes()

	v_c_full := cPVM.ToString()       // <CR><LF> at the end
	v_c := v_c_full[:len(v_c_full)-2] // remove the <CR><LF> at the end
	v_s_full := sPVM.ToString()
	v_s := v_s_full[:len(v_s_full)-2]

	// Compute the exchange hash
	// H = hash(V_C || V_S || I_C || I_S || K_S || e || f || K)
	h := sha1.New()
	h.Write([]byte(v_c))
	h.Write([]byte(v_s))
	h.Write(i_c)
	h.Write(i_s)
	h.Write(k_s)
	h.Write(e.Bytes())
	h.Write(f.Bytes())
	h.Write(k.Bytes())
	exchange_hash := h.Sum(nil)

	// sign the exchange hash
	sig := SignServerDSA(exchange_hash, hPriKey)

	response := &ServerClientKEXReply{
		MessageType:     util.SSH_MSG_KEXDH_REPLY,
		ServerHostKey:   hPubKey,
		ServerPublicKey: f,
		Signature:       sig,
	}

	b := response.Marshall()

	binPacket = CreateBinPacket(b, 16)
	b = binPacket.Marshall()

	_, err = conn.Write(b)
	if err != nil {
		fmt.Println("Write to client failed:", err.Error())
		return nil, nil, false
	}

	return k, exchange_hash, true
}

// Function that performs the Diffie-Hellman key exchange on the client side
func DH_KEX_Client(conn *net.TCPConn, group int,
	sPVM *ProtocolVersionMessage, cPVM *ProtocolVersionMessage,
	sKInit []byte, cKInit []byte,
	hPubKey *dsa.PublicKey) (*dh.DHKey, []byte, bool) {

	// Step 1:
	/*
			  C generates a random number x (1 < x < q) and computes
		      e = g^x mod p.  C sends e to S.
	*/
	e, x, g := GetKeys(group)
	if e == nil || x == nil {
		return nil, nil, false
	}

	// send my public key over to the server
	initMsg := &ClientServerKEXInit{
		MessageType:     util.SSH_MSG_KEXDH_INIT,
		ClientPublicKey: e,
	}

	b := initMsg.Marshall()

	binPacket := CreateBinPacket(b, 16)
	b = binPacket.Marshall()

	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return nil, nil, false
	}

	// Step 2 - Receive server's REPLY to KEXINIT
	buf := make([]byte, util.MAX_PACKET_SIZE)
	_, err = conn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return nil, nil, false
	}

	binPacket, _ = UnmarshallBinaryPacket(buf)
	buf = binPacket.Payload

	reply, err := UnmarshallReplyMessage(buf)
	if err != nil {
		fmt.Println("Unmarshall server's response failed:", err.Error())
		return nil, nil, false
	}

	// Step 3:
	/*
			  C verifies that K_S really is the host key for S (e.g., using
		      certificates or a local database). C then
		      computes K = f^x mod p, H = hash(V_C || V_S || I_C || I_S || K_S
		      || e || f || K), and verifies the signature s on H.
	*/

	k_s := reply.ServerHostKey

	// Received host key is the same as the one stored
	if k_s.Y.Cmp(hPubKey.Y) != 0 {
		fmt.Println("Server's host key does not match")
		return nil, nil, false
	}

	v_c_full := cPVM.ToString()
	v_c := v_c_full[:len(v_c_full)-2]
	v_s_full := sPVM.ToString()
	v_s := v_s_full[:len(v_s_full)-2]

	i_c := cKInit
	i_s := sKInit

	f := reply.ServerPublicKey

	k, err := g.ComputeKey(f, x) // k = f^x mod p
	if err != nil {
		fmt.Println("Compute key failed:", err.Error())
		return nil, nil, false
	}

	// Compute the hash
	h := sha1.New()
	h.Write([]byte(v_c))
	h.Write([]byte(v_s))
	h.Write(i_c)
	h.Write(i_s)
	h.Write(hPubKey.Y.Bytes())
	h.Write(e.Bytes())
	h.Write(f.Bytes())
	h.Write(k.Bytes())
	exchange_hash := h.Sum(nil)

	// verify the signature
	recv_hash, suc := VerifyServerDSASignature(reply.Signature, hPubKey)
	if !suc {
		fmt.Println("Server's signature verification failed")
		return nil, nil, false
	}

	// compare the two hashes
	if !bytes.Equal(exchange_hash, recv_hash) {
		fmt.Println("Server's signature verification failed")
		return nil, nil, false
	}

	return k, exchange_hash, true
}

func GenerateNewKeys(shared_secret *dh.DHKey, exchange_hash, session_id []byte, enc_algo string) *NewKeys {
	// sha1 output size is 20 bytes
	h := sha1.New()

	// Initial IV client to server: HASH(K || H || "A" || session_id)
	// (Here K is encoded as mpint and "A" as byte and session_id as raw
	// data).

	h.Write([]byte(shared_secret.String()))
	h.Write(exchange_hash)
	h.Write([]byte("A"))
	h.Write(session_id)

	iv_c2s := h.Sum(nil)

	// Initial IV server to client: HASH(K || H || "B" || session_id)
	h.Reset()
	h.Write([]byte(shared_secret.String()))
	h.Write(exchange_hash)
	h.Write([]byte("B"))
	h.Write(session_id)

	iv_s2c := h.Sum(nil)

	// Encryption key client to server: HASH(K || H || "C" || session_id)
	h.Reset()
	h.Write([]byte(shared_secret.String()))
	h.Write(exchange_hash)
	h.Write([]byte("C"))
	h.Write(session_id)

	enc_key_c2s := h.Sum(nil)

	// Encryption key server to client: HASH(K || H || "D" || session_id)
	h.Reset()

	h.Write([]byte(shared_secret.String()))
	h.Write(exchange_hash)
	h.Write([]byte("D"))
	h.Write(session_id)

	enc_key_s2c := h.Sum(nil)

	// Integrity key client to server: HASH(K || H || "E" || session_id)
	h.Reset()

	h.Write([]byte(shared_secret.String()))
	h.Write(exchange_hash)
	h.Write([]byte("E"))
	h.Write(session_id)

	int_key_c2s := h.Sum(nil)

	// Integrity key server to client: HASH(K || H || "F" || session_id)
	h.Reset()

	h.Write([]byte(shared_secret.String()))
	h.Write(exchange_hash)
	h.Write([]byte("F"))
	h.Write(session_id)

	int_key_s2c := h.Sum(nil)

	// aes blcok size is 16 bytes so we need to truncate iv
	iv_c2s = iv_c2s[:16]
	iv_s2c = iv_s2c[:16]

	if enc_algo == "3des-cbc" {
		//default block sz is 8 bytes
		iv_c2s = iv_c2s[:8]
		iv_s2c = iv_s2c[:8]
	}

	// 16 bytes key so we need to truncate
	if enc_algo == "aes128-cbc" {
		enc_key_c2s = enc_key_c2s[:16]
		enc_key_s2c = enc_key_s2c[:16]
	} else if enc_algo == "aes256-cbc" || enc_algo == "3des-cbc" {
		// we need to compute K2
		// 	K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
		//  K2 = HASH(K || H || K1)
		//  K3 = HASH(K || H || K1 || K2)
		//  ...
		//  key = K1 || K2 || K3 || ...
		h.Reset()
		h.Write([]byte(shared_secret.String()))
		h.Write(exchange_hash)
		h.Write(enc_key_c2s)
		k2 := h.Sum(nil)
		if enc_algo == "aes256-cbc" {
			enc_key_c2s = append(enc_key_c2s, k2...)[:32]
		} else {
			enc_key_c2s = append(enc_key_c2s, k2...)[:24]
		}

		h.Reset()
		h.Write([]byte(shared_secret.String()))
		h.Write(exchange_hash)
		h.Write(enc_key_s2c)
		k2 = h.Sum(nil)
		if enc_algo == "aes256-cbc" {
			enc_key_s2c = append(enc_key_s2c, k2...)[:32]
		} else {
			enc_key_s2c = append(enc_key_s2c, k2...)[:24]
		}
	}

	return &NewKeys{
		IV_C2S:     iv_c2s,
		IV_S2C:     iv_s2c,
		EncKey_C2S: enc_key_c2s,
		EncKey_S2C: enc_key_s2c,
		IntKey_C2S: int_key_c2s,
		IntKey_S2C: int_key_s2c,
	}
}

func ServerSendRecvNewKeyMessage(conn *net.TCPConn, priKey *dsa.PrivateKey) bool {
	new_key_msg := CreateNewKeysMessage()
	msg_b := new_key_msg.Marshall()
	sig := SignServerDSA(msg_b, priKey)
	binPacket := CreateBinPacket(sig, 16)
	b := binPacket.Marshall()
	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("SendNewKeyMessage: Write failed:", err.Error())
		return false
	}

	// Read the other's new key message
	b = make([]byte, util.MAX_PACKET_SIZE)
	_, err = conn.Read(b)
	if err != nil {
		fmt.Println("SendNewKeyMessage: Read failed:", err.Error())
		return false
	}

	binPacket, err = UnmarshallBinaryPacket(b)
	if err != nil {
		fmt.Println("SendNewKeyMessage: UnmarshallBinaryPacket failed:", err.Error())
		return false
	}

	msg_b = binPacket.Payload
	nkm, err := UnmarshallNewKeysMessage(msg_b)
	if err != nil {
		fmt.Println("SendNewKeyMessage: UnmarshallNewKeysMessage failed:", err.Error())
		return false
	}

	return nkm.MessageType == util.SSH_MSG_NEWKEYS
}

func ClientSendRecvNewKeyMessage(conn *net.TCPConn, pubKey *dsa.PublicKey) bool {
	new_key_msg := CreateNewKeysMessage()
	msg_b := new_key_msg.Marshall()
	binPacket := CreateBinPacket(msg_b, 16)
	b := binPacket.Marshall()
	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("SendNewKeyMessage: Write failed:", err.Error())
		return false
	}

	// Read the other's new key message
	b = make([]byte, util.MAX_PACKET_SIZE)
	_, err = conn.Read(b)
	if err != nil {
		fmt.Println("SendNewKeyMessage: Read failed:", err.Error())
		return false
	}

	binPacket, err = UnmarshallBinaryPacket(b)
	if err != nil {
		fmt.Println("SendNewKeyMessage: UnmarshallBinaryPacket failed:", err.Error())
		return false
	}

	recv_msg_b, suc := VerifyServerDSASignature(binPacket.Payload, pubKey)
	if !suc {
		fmt.Println("SendNewKeyMessage: VerifyServerDSASignature failed")
		return false
	}

	nkm, err := UnmarshallNewKeysMessage(recv_msg_b)
	if err != nil {
		fmt.Println("SendNewKeyMessage: UnmarshallNewKeysMessage failed:", err.Error())
		return false
	}

	return nkm.MessageType == util.SSH_MSG_NEWKEYS
}

func CreateNewKeysMessage() *NewKeysMessage {
	return &NewKeysMessage{
		MessageType: util.SSH_MSG_NEWKEYS,
	}
}

func (nkm *NewKeysMessage) Marshall() []byte {
	b := make([]byte, 0)
	b = append(b, nkm.MessageType)
	return b
}

func UnmarshallNewKeysMessage(b []byte) (*NewKeysMessage, error) {
	if len(b) != 1 {
		return nil, errors.New("UnmarshallNewKeysMessage: Invalid length")
	}

	if b[0] != util.SSH_MSG_NEWKEYS {
		return nil, errors.New("UnmarshallNewKeysMessage: Invalid message type")
	}

	return &NewKeysMessage{
		MessageType: b[0],
	}, nil
}
