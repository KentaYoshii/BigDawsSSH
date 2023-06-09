package util

const (
	PADDING_MIN_LENGTH = 4
	AES_BLOCK_SIZE     = 16
	COOKIE_SIZE        = 16
	MAC_LENGTH         = 20
	PADDING_MAX_LENGTH = 255
	MAX_PACKET_SIZE    = 35000

	SSH_MSG_DISCONNECT      = 1
	SSH_MSG_IGNORE          = 2
	SSH_MSG_UNIMPLEMENTED   = 3
	SSH_MSG_DEBUG           = 4
	SSH_MSG_SERVICE_REQUEST = 5
	SSH_MSG_SERVICE_ACCEPT  = 6
	SSH_MSG_KEXINIT         = 20
	SSH_MSG_NEWKEYS         = 21

	// 30 ~ 49 are for key exchange
	SSH_MSG_KEXDH_INIT  = 30
	SSH_MSG_KEXDH_REPLY = 31

	SSH_MSG_USERAUTH_REQUEST = 50
	SSH_MSG_USERAUTH_FAILURE = 51
	SSH_MSG_USERAUTH_SUCCESS = 52

	SSH_MSG_USERAUTH_PK_OK = 60
)
