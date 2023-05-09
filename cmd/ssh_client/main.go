package main

import (
	"fmt"
	"os"
	core "ssh/pkg/core"
	info "ssh/pkg/info"
)


func main() {

	if len(os.Args) != 3 {
		fmt.Println("Usage: ./ssh_client <s_address> <s_port>")
		os.Exit(1)
	}

	fmt.Println("Client Starting...")
	s_address := os.Args[1]
	s_port := os.Args[2]
	csi := &info.ClientServerInfo{} // info a/b server we are talking to
	cci := &info.ClientClientInfo{} // info a/b myself

	// Load SSH server DSA public key
	info.LoadServerDSAPubKey(csi)

	// Load Client name list
	info.LoadClientNameList(cci)

	// connect to server
	fmt.Printf("Connecting to %s:%s\n", s_address, s_port)
	ssh_conn, err := core.DoConnect(s_address, s_port)
	if err != nil {
		fmt.Println("Connection failed:", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Connected to %s\n", ssh_conn.RemoteAddr().String())

	// exchange protocol version and other info with server
	if !core.DoProtocolVersionExchange(ssh_conn, csi.ServerDSAPubKey) {
		fmt.Println("Protocol version exchange failed")
		os.Exit(1)
	}

	fmt.Printf("Protocol version exchange successful\n")

	// send client name list to server
	if !core.DoAlgorithmNegotiation(ssh_conn, csi.ServerDSAPubKey, cci) {
		fmt.Println("Algorithm negotiation failed")
		os.Exit(1)
	}

	for {

	}
}