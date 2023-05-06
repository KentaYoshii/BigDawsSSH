package connection

import (
	"net"
	"fmt"
)

func DoConnect(s_address string, s_port string) (*net.TCPConn, error) {
	addr_str := fmt.Sprintf("%s:%s", s_address, s_port)
	addr_str_n, err := net.ResolveTCPAddr("tcp4", addr_str)
	if err != nil {
		fmt.Println("ResolveTCPAddr failed:", err.Error())
		return nil, err
	}
	conn, err := net.DialTCP("tcp4", nil, addr_str_n)
	if err != nil {
		fmt.Println("Dial failed:", err.Error())
		return nil, err
	}
	return conn, nil
}