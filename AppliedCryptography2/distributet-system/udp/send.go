package udp

import (
	"encoding/json"
	"fmt"
	"net"
)

func (m Message) SendUDPMsg(sendConn *net.UDPConn) {

	jsonData, err := json.Marshal(m)
	if err != nil {
		fmt.Println("Error encoding message:", err)
	} else {
		sendConn.Write(jsonData)
	}
}
