package main

import (
	"fmt"
	"os"
	core "ssh/pkg/core"
)

// ./ssh_client <s_address> <s_port> 
func main() {
	fmt.Println("Client Starting...")
	s_address := os.Args[1]
	s_port := os.Args[2]
	fmt.Printf("Connecting to %s:%s\n", s_address, s_port)

	// connect to server
	ssh_conn, err := core.DoConnect(s_address, s_port)
	if err != nil {
		fmt.Println("Connection failed:", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Connected to %s\n", ssh_conn.RemoteAddr().String())

	// exchange protocol version and other info with server
	if !core.DoProtocolVersionExchange(ssh_conn) {
		fmt.Println("Protocol version exchange failed")
		os.Exit(1)
	}

	fmt.Printf("Protocol version exchange successful\n")

	for {
		
	}
}