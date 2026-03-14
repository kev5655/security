package io

import (
	"bufio"
	"fmt"
	"strings"
)

func ReadInput(scanner *bufio.Scanner) (string, error) {
	fmt.Print("> ")
	if !scanner.Scan() {
		return "", fmt.Errorf("failed to read input")
	}

	return scanner.Text(), nil
}

type ParsedResult interface {
	result()
}

type Discover struct {
	Sender string
}

func (r Discover) result() {}

type DirectMessage struct {
	Sender   string
	Receiver string
	Content  string
}

func (r DirectMessage) result() {}

type ParseError struct {
	ErrorMsg string
}

func (r ParseError) result() {}

func ParseInput(text, name string) ParsedResult {
	parts := strings.SplitN(text, " ", 2)
	if parts[0] == "discover" {
		return Discover{
			Sender: name,
		}
	}
	if len(parts) == 2 {
		return DirectMessage{
			Sender:   name,
			Receiver: parts[0],
			Content:  parts[1],
		}
	}
	return ParseError{
		ErrorMsg: "Format: <receiver_name> <message> | <discover>",
	}
}
