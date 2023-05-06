package main

import (
	"fmt"
	// "ssh/pkg/protocol"
	conn "ssh/pkg/connection"
	cli "ssh/pkg/cli"
	info "ssh/pkg/info"
)

func main() {

	// Set up listening socket
	fmt.Println("Server Starting...")
	port := "3000"
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
				continue
			}
			handler := cli.GetHandler(cmdIdx)
			handler(*serverInfo)
			continue
		case signal := <- serverInfo.CloseChan:
			if signal {
				fmt.Println("Closing server...")
				// TODO: Close all connections
				return
			}
			continue
		}
	}
}


