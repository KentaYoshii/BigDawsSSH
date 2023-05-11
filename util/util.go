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