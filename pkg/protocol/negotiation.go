package protocol

import (
	"errors"
)

type AgreedNegotiation struct {
	// The agreed upon algorithms
	Kex_algorithm             string
	Server_host_key_algorithm string
	Encryption_algorithm      string
	Mac_algorithm             string
	Compression_algorithm     string
	Language                  string
}

func DoNegotiation(canm *ClientAlgorithmNegotiationMessage, sanm *ServerAlgorithmNegotiationMessage) (*AgreedNegotiation, error) {
	res := &AgreedNegotiation{}

	// * Kex_algorithm
	// Simply return the first common algorithm that appears in both lists
	for _, kex := range canm.Kex_algorithms {
		for _, skex := range sanm.Kex_algorithms {
			if kex == skex {
				res.Kex_algorithm = kex
				break
			}
		}
		if res.Kex_algorithm != "" {
			break
		}
	}

	if res.Kex_algorithm == "" {
		return nil, errors.New("server does not support any of the client's key exchange algorithms")
	}

	// * Server_host_key_algorithm
	// ! Server only supports dsa for now (only signature-capable)
	for _, shka := range sanm.Server_host_key_algorithms {
		if shka == "ssh-dss" {
			res.Server_host_key_algorithm = shka
			break
		}
	}

	if res.Server_host_key_algorithm == "" {
		return nil, errors.New("server does not support any of the client's host key algorithms")
	}

	// * Encryption_algorithm
	// First algorithm in the client's list that appears in the server's list
	for _, ea := range canm.Encryption_algorithms_client_to_server {
		for _, sea := range sanm.Encryption_algorithms_server_to_client {
			if ea == sea {
				res.Encryption_algorithm = ea
				break
			}
		}
		if res.Encryption_algorithm != "" {
			break
		}
	}

	if res.Encryption_algorithm == "" {
		return nil, errors.New("server does not support any of the client's encryption algorithms")
	}

	// * Mac_algorithm
	// same as encryption algorithm
	for _, ma := range canm.Mac_algorithms_client_to_server {
		for _, sma := range sanm.Mac_algorithms_server_to_client {
			if ma == sma {
				res.Mac_algorithm = ma
				break
			}
		}
		if res.Mac_algorithm != "" {
			break
		}
	}

	if res.Mac_algorithm == "" {
		return nil, errors.New("server does not support any of the client's mac algorithms")
	}

	// * Compression_algorithm
	// same as encryption algorithm
	for _, ca := range canm.Compression_algorithms_client_to_server {
		for _, sca := range sanm.Compression_algorithms_server_to_client {
			if ca == sca {
				res.Compression_algorithm = ca
				break
			}
		}
		if res.Compression_algorithm != "" {
			break
		}
	}

	if res.Compression_algorithm == "" {
		return nil, errors.New("server does not support any of the client's compression algorithms")
	}

	// * Language
	// we don't care about this
	res.Language = "none"

	return res, nil

}
