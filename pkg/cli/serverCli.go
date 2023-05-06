package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	info "ssh/pkg/info"
)

const (
	HELP = iota
	QUIT
	LIST
)

func CmdToIndex(cmd string) int {
	switch cmd {
	case "help":
		return HELP
	case "quit":
		return QUIT
	case "list":
		return LIST
	default:
		return -1
	}
}

type HandlerFn func(info.ServerInfo) error

func GetHandler(cmdIdx int) HandlerFn {
	switch cmdIdx {
	case HELP:
		return DoHelp
	case QUIT:
		return DoQuit
	case LIST:
		return DoList
	default:
		return nil
	}
}

// Handle the "help" command
// Print all the commands and their descriptions 
func DoHelp(si info.ServerInfo) error {
	fmt.Printf("Supported commands for ssh server %s \n:", si.Hostname)
    fmt.Printf("%-10s%s\n", "help", "Display this help message")
    fmt.Printf("%-10s%s\n", "list", "List all items")
    fmt.Printf("%-10s%s\n", "exit", "Exit the program")

	return nil
}

// Handle the "quit" command
// Send true to the CloseChan to signal the server to close
func DoQuit(si info.ServerInfo) error {
	si.CloseChan <- true
	return nil
}

// Handle the "list" command
// Print all the clients connected to the server
func DoList(si info.ServerInfo) error {
	// atomicity
	si.ClientsMutex.Lock()
	defer si.ClientsMutex.Unlock()

	fmt.Println("Clients connected to server:")
	for _, client := range si.Clients {
		fmt.Println(client.Address)
	}
	return nil
}

func ParseCLI(cliChan chan []string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		input := scanner.Text()
		input = strings.TrimSpace(input)
		input = strings.ToLower(input)
		tokens := strings.Fields(input)
		cliChan <- tokens
	}

	if err := scanner.Err(); err != nil {
		fmt.Print("Error reading from stdin: ", err)
		os.Exit(1)
	}
}