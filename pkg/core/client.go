package connection

import (
	"net"
	"fmt"
	proto "ssh/pkg/protocol"
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

func DoProtocolVersionExchange(conn *net.TCPConn) bool {
	client_pvm := proto.CreateProtocolVersionMessage()

	// send client's protocol version
	b := client_pvm.Marshall()
	_, err := conn.Write(b)
	if err != nil {
		fmt.Println("Write to server failed:", err.Error())
		return false
	}

	// read server's protocol version
	buf := make([]byte, 256)
    _, err = conn.Read(buf)
	if err != nil {
		fmt.Println("Read from server failed:", err.Error())
		return false
	}

	// unmarshall server's protocol version
	_, err = client_pvm.UnmarshallAndVerify(buf)

	return err == nil
}