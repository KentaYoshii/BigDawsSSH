package util

func GetBlockSize(algo string) uint8 {
	switch algo {
	case "aes128-cbc":
		return 16
	case "aes256-cbc":
		return 16
	case "3des-cbc":
		return 8
	}
	return 0
}

func GetRSAFilePath(user string) (string, string) {
	switch user {
	case "client":
		return "./data/rsa/client/pubkey.pem", "./data/rsa/client/privkey.pem"
	case "client2":
		return "./data/rsa/client2/pubkey.pem", "./data/rsa/client2/privkey.pem"
	}
	return "",""
}