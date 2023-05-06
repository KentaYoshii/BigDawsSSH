package main

import (
	"fmt"
	"os"
	conn "ssh/pkg/connection"
)

// ./ssh_client <s_address> <s_port> 
func main() {
	fmt.Println("Client Starting...")
	s_address := os.Args[1]
	s_port := os.Args[2]
	fmt.Printf("Connecting to %s:%s\n", s_address, s_port)

	// connect to server
	ssh_conn, err := conn.DoConnect(s_address, s_port)
	if err != nil {
		fmt.Println("Connection failed:", err.Error())
		os.Exit(1)
	}

	fmt.Printf("Connected to %s\n", ssh_conn.RemoteAddr().String())

	for {
		
	}
}