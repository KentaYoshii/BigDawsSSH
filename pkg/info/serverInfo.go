package info

import (
	"crypto/dsa"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	protocol "ssh/pkg/protocol"
	"sync"
	dh "github.com/monnand/dhkx"
)

type ClientServerInfo struct {
	// Client use
	ServerDSAPubKey *dsa.PublicKey
	ServerConn      *net.TCPConn
	AgreedAlgorithm *protocol.AgreedNegotiation
	PVM             *protocol.ProtocolVersionMessage
	KInitMSG		[]byte
	SharedSecret  	*dh.DHKey
	ExchangeHash  	[]byte
	SessionIdentifier []byte // Identifier for this session set to the first hash output of the KEX. IMMUTABLE
	Keys 			*protocol.NewKeys
}

type ServerInfo struct {
	// Basic info a/b the server
	Hostname     string
	Port         string
	ListenerConn *net.TCPListener

	// Info about the clients
	NewID             int
	Clients           []*ServerClientInfo
	ClientsAlgorithms map[int]*protocol.AgreedNegotiation

	// Channels
	CloseChan chan bool
	CmdChan   chan []string

	// Mutexes
	ClientsMutex *sync.Mutex
	ClientWg     *sync.WaitGroup

	// DSA
	DSAPrivKey *dsa.PrivateKey
	DSAPubKey  *dsa.PublicKey

	// Protocol
	PVM      *protocol.ProtocolVersionMessage
	KInitMSG []byte

	// Name-Lists (comma-separated string)
	// Supported algorithm on the ssh server in the order of preference
	// The first in each of these is the "guessed" algorithm
	Kex_algorithms                          []string
	Server_host_key_algorithms              []string
	Encryption_algorithms_server_to_client  []string
	Mac_algorithms_server_to_client         []string
	Compression_algorithms_server_to_client []string
	Languages_server_to_client              []string
	First_kex_packet_follows                bool
}

func CreateNewServerInfo(hostname string, port string, listenerConn *net.TCPListener) *ServerInfo {
	return &ServerInfo{
		Hostname:          hostname,
		Port:              port,
		ListenerConn:      listenerConn,
		NewID:             0,
		Clients:           make([]*ServerClientInfo, 0),
		ClientsAlgorithms: make(map[int]*protocol.AgreedNegotiation),
		CloseChan:         make(chan bool, 1),
		CmdChan:           make(chan []string),
		ClientsMutex:      &sync.Mutex{},
		ClientWg:          &sync.WaitGroup{},
		PVM:               protocol.CreateProtocolVersionMessage(),
	}
}

func LoadDSAKeys(si *ServerInfo) {
	// Load server DSA private key
	privKey, err := protocol.ParseDSAPrivateKeyFromFile("./data/keys/dsa-key.pem")
	if err != nil {
		fmt.Println("Error loading server DSA private key:", err.Error())
		os.Exit(1)
	}

	// Load server DSA public key
	pubKey, err := protocol.ParseDSAPublicKeyFromFile("./data/keys/dsa-public-key.pem")
	if err != nil {
		fmt.Println("Error loading server DSA public key:", err.Error())
		os.Exit(1)
	}

	si.DSAPrivKey = privKey
	si.DSAPubKey = pubKey
}

func LoadServerDSAPubKey(csi *ClientServerInfo) {
	// Load server DSA public key
	pubKey, err := protocol.ParseDSAPublicKeyFromFile("./data/keys/dsa-public-key.pem")
	if err != nil {
		fmt.Println("Error loading server DSA public key:", err.Error())
		os.Exit(1)
	}

	csi.ServerDSAPubKey = pubKey
}

// Function that loads the csv file that contains the list of supported algorithms
// for the ssh server in the order of preference
func LoadServerNameList(si *ServerInfo) {
	// open file
	file, err := os.Open("./data/namelist/server.csv")
	if err != nil {
		fmt.Println("Error opening server name list:", err.Error())
		os.Exit(1)
	}
	defer file.Close()

	// each line is a list of comma-separated strings where first token is the name of the name-list (e.g., kex_algorithms)
	reader := csv.NewReader(file)

	for idx := 0; idx < 8; idx++ {
		if idx == 0 {
			// skip first line (header)
			_, err := reader.Read()
			if err != nil {
				fmt.Println("Error reading server name list:", err.Error())
				os.Exit(1)
			}
			continue
		}
		// read line
		record, err := reader.Read()
		if err != nil {
			fmt.Println("Error reading server name list:", err.Error())
			os.Exit(1)
		}
		// first token is the name of the name-list
		name_list_name := record[0]
		// rest of the tokens are the comma-separated strings
		tokens := record[1:]
		// create name-list
		name_list := make([]string, 0)
		for _, token := range tokens {
			if token != "" {
				name_list = append(name_list, token)
			}
		}
		// add name-list to server info
		switch name_list_name {
		case "kex_algorithms":
			si.Kex_algorithms = name_list
		case "server_host_key_algorithms":
			si.Server_host_key_algorithms = name_list
		case "encryption_algorithms_server_to_client":
			si.Encryption_algorithms_server_to_client = name_list
		case "mac_algorithms_server_to_client":
			si.Mac_algorithms_server_to_client = name_list
		case "compression_algorithms_server_to_client":
			si.Compression_algorithms_server_to_client = name_list
		case "languages_server_to_client":
			si.Languages_server_to_client = name_list
		case "first_kex_packet_follows":
			si.First_kex_packet_follows = name_list[0] == "true"
		default:
			fmt.Println("Error parsing server name list:", err.Error())
			os.Exit(1)
		}
	}
}
