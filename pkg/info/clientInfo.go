package info

import (
	"net"
	"os"
	"encoding/csv"
	"fmt"
)

type ServerClientInfo struct {
	// Server use
	ID      int
	Address string
	Conn    *net.TCPConn
	Status  int
}

type ClientClientInfo struct {
	// Client use
	Kex_algorithms                          []string
	Server_host_key_algorithms              []string
	Encryption_algorithms_client_to_server  []string
	Mac_algorithms_client_to_server         []string
	Compression_algorithms_client_to_server []string
	Languages_client_to_server              []string
	First_kex_packet_follows                bool
}

func CreateNewClientInfo(id int, address string, conn *net.TCPConn) *ServerClientInfo {
	return &ServerClientInfo{
		ID:      id,
		Address: address,
		Conn:    conn,
		Status:  0,
	}
}

// Function that loads the csv file that contains the list of supported algorithms
// for the ssh server in the order of preference
func LoadClientNameList(cci *ClientClientInfo) {
	// open file
	file, err := os.Open("./data/namelist/client.csv")
	if err != nil {
		fmt.Println("Error opening client name list:", err.Error())
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
			fmt.Println("Error reading client name list:", err.Error())
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
			cci.Kex_algorithms = name_list
		case "server_host_key_algorithms":
			cci.Server_host_key_algorithms = name_list
		case "encryption_algorithms_client_to_server":
			cci.Encryption_algorithms_client_to_server = name_list
		case "mac_algorithms_client_to_server":
			cci.Mac_algorithms_client_to_server = name_list
		case "compression_algorithms_client_to_server":
			cci.Compression_algorithms_client_to_server = name_list
		case "languages_client_to_server":
			cci.Languages_client_to_server = name_list
		case "first_kex_packet_follows":
			cci.First_kex_packet_follows = name_list[0] == "true"
		default:
			fmt.Println("Error parsing client name list:", err.Error())
			os.Exit(1)
		}
	}
}
