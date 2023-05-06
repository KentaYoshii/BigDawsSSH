package main

import (
	"fmt"
	"os"
	// "ssh/pkg/protocol"
	conn "ssh/pkg/connection"
	cli "ssh/pkg/cli"
	info "ssh/pkg/info"
)

// ./ssh_server <port>
func main() {

	// Set up listening socket
	fmt.Println("Server Starting...")
	port := os.Args[1]
	listener := conn.CreateNewListener(port)

	// Set up ServerInfo Struct
	serverInfo := info.CreateNewServerInfo("localhost", port, listener)

	// Enter the accept loop
	fmt.Println("Ready to accept connections...")
	go conn.AcceptNewConnection(serverInfo)

	// Start the command loop
	go cli.ParseCLI(serverInfo.CmdChan)

	for {
		select {
		case cmd := <-serverInfo.CmdChan:
			cmdIdx := cli.CmdToIndex(cmd[0])
			if cmdIdx == -1 {
				fmt.Println("Command not supported")
				fmt.Printf("> ")
				continue
			}
			handler := cli.GetHandler(cmdIdx)
			handler(serverInfo)
		case signal := <-serverInfo.CloseChan:
			if signal {
				fmt.Println("Closing server...")
				// TODO: Close all connections
				return
			}
			fmt.Printf("> ")
		}
	}
}


