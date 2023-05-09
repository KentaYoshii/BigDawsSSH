package protocol

type AgreedNegotiation struct {
	// The agreed upon algorithms
	Kex_algorithm             string
	Server_host_key_algorithm string
	Encryption_algorithm      string
	Mac_algorithm             string
	Compression_algorithm     string
	Language                  string
}

func DoNegotiation(canm *ClientAlgorithmNegotiationMessage, sanm *ServerAlgorithmNegotiationMessage) *AgreedNegotiation {
	return nil
}
