package protocol

import (
	"fmt"
)

func CheckError(err error, protocol string) bool {
	if err != nil {
		fmt.Printf("[%s] Error: %s\n", protocol, err.Error())
		return true
	} 
	return false
}