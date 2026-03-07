package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"distributed/io"
	"distributed/udp"
)

type RoutingTable map[string]string

var (
	name   string
	number int
	table  = make(RoutingTable)
)

func main() {
	name = os.Args[1:][0]
	number, _ = strconv.Atoi(strings.Replace(name, "node", "", 1))

	fmt.Printf("Welcome! You are connected as: %s\n", name)

	multicastAddr := "224.0.0.1:9999"

	addr, _ := net.ResolveUDPAddr("udp", multicastAddr)
	sendConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		fmt.Println("Sender error:", err)
		return
	}
	defer sendConn.Close()

	go func() {
		addr, _ := net.ResolveUDPAddr("udp", multicastAddr)

		conn, err := net.ListenMulticastUDP("udp", nil, addr)
		if err != nil {
			fmt.Println("Receiver error:", err)
			return
		}
		defer conn.Close()

		buffer := make([]byte, 1024)

		for {
			n, _, err := conn.ReadFromUDP(buffer)
			if err != nil {
				continue
			}

			msg, err := udp.Parse(buffer, n)
			if err != nil {
				continue
			}

			// Skip my own messages
			if msg.Sender == name {
				continue
			}

			if strings.HasPrefix(msg.Content, "discover") {
				// This is for Clique Routing
				parts := strings.SplitN(msg.Content, " ", 3)
				if len(parts) == 3 {
					senderName := parts[1]
					senderAddr := parts[2]
					table[senderName] = senderAddr
					fmt.Printf("\r-> Discovered %s at %s\n> ", senderName, senderAddr)
				}

			}

			// Process message if it's for me
			if msg.Receiver == name {
				fmt.Printf("\r-> %s: %s\n> ", msg.Sender, msg.Content)
			}

		}
	}()

	// 5. Read input from the user's keyboard in an infinite loop
	fmt.Println("Type a message and press Enter to send (Ctrl+C to quit):")
	scanner := bufio.NewScanner(os.Stdin)

	for {
		text, err := io.ReadInput(scanner)
		if err != nil {
			break
		}

		switch v := io.ParseInput(text, name).(type) {
		case io.Discover:
			sendDiscoverMessage(sendConn)
		case io.DirectMessage:
			sendMessage(sendConn, table[v.Receiver], v.Content)
		case io.ParseError:
			fmt.Println(v.ErrorMsg)
		}
	}
}

func sendDiscoverMessage(sendConn *net.UDPConn) {
	udp.Message{
		Sender:   name,
		Receiver: "",
		Content:  "discover " + name + " " + name,
	}.SendUDPMsg(sendConn)
}

func sendMessage(sendConn *net.UDPConn, receiver string, content string) {
	udp.Message{
		Sender:   name,
		Receiver: receiver,
		Content:  content,
	}.SendUDPMsg(sendConn)
}
