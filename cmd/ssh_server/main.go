package main

import (
	"fmt"
	"os"
	// "ssh/pkg/protocol"
	core "ssh/pkg/core"
	cli "ssh/pkg/cli"
	info "ssh/pkg/info"
)

// ./ssh_server <port>
func main() {

	// Set up listening socket
	fmt.Println("Server Starting...")
	port := os.Args[1]
	listener := core.CreateNewListener(port)

	// Set up ServerInfo Struct
	serverInfo := info.CreateNewServerInfo("localhost", port, listener)

	// Enter the accept loop
	fmt.Println("Ready to accept connections...")
	go core.AcceptNewConnection(serverInfo)

	// Start the command loop
	go cli.ParseCLI(serverInfo.CmdChan)

	for {
		select {
		case cmd := <-serverInfo.CmdChan:
			cmdIdx := cli.CmdToIndex(cmd[0])
			if cmdIdx == -1 {
				fmt.Println("Command not supported")
				continue
			}
			handler := cli.GetHandler(cmdIdx)
			handler(serverInfo)
		case signal := <-serverInfo.CloseChan:
			if signal {
				fmt.Println("Closing client connections...")
				core.CloseConnection(serverInfo)
				fmt.Println("Closing server...")
				return
			}
		}
	}
}


