//go:build ignore

package main

import (
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/sha3"

	"fmt"
)

// echo -n "hey" | sha256sum
// # or
// printf "hey" | sha256sum

func main() {

	var input string
	fmt.Print("Enter data to hash: ")
	_, err := fmt.Scanln(&input)
	if err != nil {
		fmt.Printf("Error reading input: %v\n", err)
		return
	}

	fmt.Printf("You entered: %s\n", input)

	block256 := sha256.Sum256([]byte(input))
	fmt.Printf("SHA-256: %x\n", block256)

	block512 := sha512.Sum512([]byte(input))
	fmt.Printf("SHA-512: %x\n", block512)

	block3 := sha3.Sum256([]byte(input))
	fmt.Printf("SHA3-256: %x\n", block3)

	block3_512 := sha3.Sum512([]byte(input))
	fmt.Printf("SHA3-512: %x\n", block3_512)
}
