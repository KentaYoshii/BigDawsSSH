package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	info "ssh/pkg/info"
	"github.com/fatih/color"
	"encoding/csv"
	"text/tabwriter"
)

const (
	HELP = iota
	QUIT
	LIST
	INFO
)

func CmdToIndex(cmd string) int {
	switch cmd {
	case "help":
		return HELP
	case "quit":
		return QUIT
	case "list":
		return LIST
	case "info":
		return INFO
	default:
		return -1
	}
}

type HandlerFn func(*info.ServerInfo) error

func GetHandler(cmdIdx int) HandlerFn {
	switch cmdIdx {
	case HELP:
		return DoHelp
	case QUIT:
		return DoQuit
	case LIST:
		return DoList
	case INFO:
		return DoInfo
	default:
		return nil
	}
}

// Handle the "help" command
// Print all the commands and their descriptions 
func DoHelp(si *info.ServerInfo) error {
	// Define the colors for the table
	headerColor := color.New(color.FgGreen, color.Bold)
	commandColor := color.New(color.FgWhite, color.Bold)
	descColor := color.New(color.FgWhite)

	// Define the table width and spacing
	tableWidth := 30
	spacing := (80 - tableWidth) / 2

	// Generate the padding string
	padding := strings.Repeat(" ", spacing)

	// Print the table header
	fmt.Println()
	headerColor.Println(padding + "Supported commands:")
	fmt.Println(padding + "+------------+--------------------------+")
	fmt.Println(padding + "| Command    | Description              |")
	fmt.Println(padding + "+------------+--------------------------+")

	// Print each command and description with color
	commandColor.Printf(padding + "| ")
	descColor.Printf("%-10s", "help")
	fmt.Print(commandColor.Sprintf(" | "))
	descColor.Printf("%-24s", "Display help message")
	fmt.Println(commandColor.Sprintf(" |"))

	commandColor.Printf(padding + "| ")
	descColor.Printf("%-10s", "list")
	fmt.Print(commandColor.Sprintf(" | "))
	descColor.Printf("%-24s", "List all items")
	fmt.Println(commandColor.Sprintf(" |"))

	commandColor.Printf(padding + "| ")
	descColor.Printf("%-10s", "quit")
	fmt.Print(commandColor.Sprintf(" | "))
	descColor.Printf("%-24s", "Exit the program")
	fmt.Println(commandColor.Sprintf(" |"))

	commandColor.Printf(padding + "| ")
	descColor.Printf("%-10s", "info")
	fmt.Print(commandColor.Sprintf(" | "))
	descColor.Printf("%-24s", "Display server info")
	fmt.Println(commandColor.Sprintf(" |"))

	// Print the table footer
	fmt.Println(padding + "+------------+--------------------------+")
	fmt.Println()
	return nil
}

// Function that prints the server's accepted algorithms
func DoInfo(si *info.ServerInfo) error {
	// Define the colors for the table
	headerColor := color.New(color.FgGreen, color.Bold)
	descColor := color.New(color.FgWhite)

	// hard-coded for now :(
	data := [][]string{
		{"Key Exchange", "dh-g1-sha1"},
		{"Host Key", "ssh-dss"},
		{"Encryption", "aes128-cbc"},
		{"Mac Scheme", "hmac-sha1"},
		{"Compression", "none"},
		{"Languages", "none"},
	}

	// Create a new CSV writer
	writer := csv.NewWriter(os.Stdout)

	// Set the delimiter to a tab character for a neater format
	writer.Comma = '\t'

	// Create a new tabwriter with padding and alignment settings
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Write the CSV data to the tabwriter
	// Define the table width and spacing
	tableWidth := 30
	spacing := (80 - tableWidth) / 2
	padding := strings.Repeat(" ", spacing)

	// Print the table header
	fmt.Println()
	headerColor.Println(padding + "Server info:")
	fmt.Println(padding + "+---------------------------+")
	fmt.Println(padding + "| Algorithm                 |")
	fmt.Println(padding + "+---------------------------+")

	for _, record := range data {
		fmt.Printf(padding + "| ")
		descColor.Printf("%s\t| %-10s", record[0], record[1])
		fmt.Println(" |")
	}

	// Print the table footer
	fmt.Println(padding + "+---------------------------+")

	// Flush the tabwriter to display the output
	w.Flush()

	fmt.Println()
	return nil
}

// Handle the "quit" command
// Send true to the CloseChan to signal the server to close
func DoQuit(si *info.ServerInfo) error {
	si.CloseChan <- true
	return nil
}

// Handle the "list" command
// Print all the clients connected to the server
func DoList(si *info.ServerInfo) error {
	// atomicity
	si.ClientsMutex.Lock()
	defer si.ClientsMutex.Unlock()

	// Define the colors for the table
	headerColor := color.New(color.FgGreen, color.Bold)
	idColor := color.New(color.FgWhite)
	addrColor := color.New(color.FgWhite)
	statusColor := color.New(color.FgWhite)

	// Define the table width and spacing
	tableWidth := 30
	spacing := (80 - tableWidth) / 2

	// Generate the padding string
	padding := strings.Repeat(" ", spacing)

	// Print the table header
	headerColor.Println(padding + "Connected clients:")
	fmt.Println(padding + "+-------+---------------------------+----------+")
	fmt.Println(padding + "| ID    | Address                   | Status   |")
	fmt.Println(padding + "+-------+---------------------------+----------+")

	// Print each client information with color
	for _, c := range si.Clients {
		idColor.Printf(padding + "| %-5d ", c.ID)
		fmt.Print(idColor.Sprintf("| "))
		addrColor.Printf("%-25s", c.Address)
		fmt.Print(addrColor.Sprintf(" | "))
		statusColor.Printf("%-8d", c.Status)
		fmt.Println(statusColor.Sprintf(" |"))
	}

	// Print the table footer
	fmt.Println(padding + "+-------+---------------------------+----------+")
	fmt.Println()
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