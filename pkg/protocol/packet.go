package protocol

import (
	"bytes"
	"encoding/binary"
	mrand "math/rand"
	util "ssh/util"
	"time"
)

type EncryptedBinaryPacket struct {
	Ciphertext []byte
	MAC        []byte
}

type BinaryPacket struct {
	// The length of the packet in bytes, not including 'mac' or the 'packet_length' field itself.
	Packet_Length uint32
	// The length of 'random padding' (bytes).
	Padding_Length uint8
	// The actual content of the packet
	// ! if compression is enabled, this is compressed
	Payload []byte
	// Arbitrary-length padding, such that the total length of (packet_length || padding_length || payload || random padding)
	// is a multiple of the cipher block size or 8, whichever is larger.
	// 4 <= padding_length <= 255
	Padding []byte
}

// Function that generates a random cookie of length 16
// RFC 4253 section 7.1
func GenerateCookie() []byte {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	cookie := make([]byte, util.COOKIE_SIZE)
	r.Read(cookie)
	return cookie
}

func GenerateRandomPadding(sz uint8) []byte {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	padding := make([]byte, sz)
	r.Read(padding)
	return padding
}

func CreateBinPacket(payload []byte) *BinaryPacket {
	bp := &BinaryPacket{}
	bp.Payload = payload
	pay_len := uint32(len(payload))
	// 4 bytes for packet length (uint32)
	// 1 for padding length (uint8)
	curr := pay_len + 4 + 1 
	if curr%16 == 0 {
		bp.Padding_Length = 16 // 4 byte minimum padding
	} else {
		bp.Padding_Length = uint8(16 - (curr % 16))
		if bp.Padding_Length < 4 {
			bp.Padding_Length += 16
		}
	}
	bp.Padding = GenerateRandomPadding(bp.Padding_Length)
	bp.Packet_Length = uint32(bp.Padding_Length) + pay_len + 1
	return bp
}

func (ebp *EncryptedBinaryPacket) Marshall() []byte {
	b := new(bytes.Buffer)
	c_len := uint32(len(ebp.Ciphertext))
	binary.Write(b, binary.BigEndian, c_len)
	b.Write(ebp.Ciphertext)
	mac_len := uint32(len(ebp.MAC))
	binary.Write(b, binary.BigEndian, mac_len)
	b.Write(ebp.MAC)
	return b.Bytes()
}

func UnmarshallEncryptedBinaryPacket(b []byte) (*EncryptedBinaryPacket, error) {
	var curr uint32 = 0
	ebp := &EncryptedBinaryPacket{}
	c_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	ebp.Ciphertext = b[curr : curr+c_len]
	curr += uint32(len(ebp.Ciphertext))
	mac_len := binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	ebp.MAC = b[curr : curr+mac_len]
	return ebp, nil
}

func (bp *BinaryPacket) Marshall() []byte {
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, bp.Packet_Length)
	binary.Write(b, binary.BigEndian, bp.Padding_Length)
	b.Write(bp.Payload)
	b.Write(bp.Padding)
	return b.Bytes()
}

// [000 000 000 012 7 a b c d ass fkje efjk kjef kjfk jkej gjkj]
// packet length = 12
// padding length = 7
func UnmarshallBinaryPacket(b []byte) (*BinaryPacket, error) {
	var curr uint32 = 0
	bp := &BinaryPacket{}
	bp.Packet_Length = binary.BigEndian.Uint32(b[curr : curr+4])
	curr += 4
	bp.Padding_Length = b[curr]
	curr += 1
	pay_len := bp.Packet_Length - uint32(bp.Padding_Length) - 1
	bp.Payload = b[curr : curr+pay_len]
	curr += uint32(len(bp.Payload))
	bp.Padding = b[curr : curr+uint32(bp.Padding_Length)]
	curr += uint32(len(bp.Padding))
	return bp, nil
}
