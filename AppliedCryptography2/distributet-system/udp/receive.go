package udp

import "encoding/json"

func Parse(buffer []byte, len int) (Message, error) {
	var msg Message
	err := json.Unmarshal(buffer[:len], &msg)
	if err != nil {
		return Message{}, err
	}
	return msg, nil
}
