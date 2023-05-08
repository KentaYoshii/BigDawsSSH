package protocol

import (
	util "ssh/util"
	mrand "math/rand"
	crand "crypto/rand"
    "time"
)

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
	// Message Authentication Code
	MAC []byte
}

// Function that generates a random cookie of length 16
// RFC 4253 section 7.1
func GenerateCookie() []byte {
	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	cookie := make([]byte, util.COOKIE_SIZE)
	r.Read(cookie)
	return cookie
}

// Function that generates a random padding of length 4 <= padding_length <= 255
func GenerateRandomPadding() []byte {
	// Seed the random number generator with the current time
    r := mrand.New(mrand.NewSource(time.Now().UnixNano()))

    // Generate a random integer between 0 and 14
    randomOffset := r.Intn(util.AES_BLOCK_SIZE-1) 

    // Calculate the corresponding multiple of 16 between 4 and 255
    randomInt := (randomOffset * 16) + util.AES_BLOCK_SIZE

	if randomInt % util.AES_BLOCK_SIZE != 0 {
		panic("error: randomInt is not a multiple of 16")
	}

	// Create a random byte array of the appropriate length
	randomPadding := make([]byte, randomInt)
	crand.Read(randomPadding)

	return randomPadding
}