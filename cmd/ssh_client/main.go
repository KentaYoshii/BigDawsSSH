package main

import (
	"fmt"
	"os"
	core "ssh/pkg/core"
	info "ssh/pkg/info"
	proto "ssh/pkg/protocol"
)

func main() {

	if len(os.Args) != 4 {
		fmt.Println("Usage: ./ssh_client <s_address> <s_port> <name-list file path>")
		os.Exit(1)
	}

	fmt.Println("Client Starting...")
	s_address := os.Args[1]
	s_port := os.Args[2]
	name_list_path := os.Args[3]
	csi := &info.ClientServerInfo{} // info a/b server we are talking to
	cci := &info.ClientClientInfo{} // info a/b myself

	// Load SSH server DSA public key
	info.LoadServerDSAPubKey(csi)

	// Load Client name list
	info.LoadClientNameList(cci, name_list_path)

	// connect to server
	fmt.Printf("Connecting to %s:%s\n", s_address, s_port)
	ssh_conn, err := core.DoConnect(s_address, s_port)
	if err != nil {
		fmt.Println("Connection failed:", err.Error())
		os.Exit(1)
	}

	csi.ServerConn = ssh_conn

	fmt.Printf("Connected to %s\n", ssh_conn.RemoteAddr().String())

	// exchange protocol version and other info with server
	if !core.DoProtocolVersionExchange(csi, cci) {
		fmt.Println("Protocol version exchange failed")
		os.Exit(1)
	}

	fmt.Printf("Protocol version exchange successful\n")

	// do algorithm negotiation
	if !core.DoAlgorithmNegotiation(csi, cci) {
		fmt.Println("Algorithm negotiation failed")
		os.Exit(1)
	}

	fmt.Printf("Algorithm negotiation successful\n")

	kex_algo := csi.AgreedAlgorithm.Kex_algorithm
	group := proto.GetDHGroup(kex_algo)

	// do key exchange
	k, exh, suc := proto.Do_KEX_Client(csi.AgreedAlgorithm.Kex_algorithm)(csi.ServerConn,
		group, csi.PVM, cci.ClientPVM, csi.KInitMSG, cci.ClientKInitMSG,
		csi.ServerDSAPubKey)
	
	if !suc {
		fmt.Println("Key exchange failed")
		os.Exit(1)
	}

	csi.SharedSecret = k
	csi.ExchangeHash = exh

	fmt.Printf("Key exchange successful\n")

	for {

	}
}
