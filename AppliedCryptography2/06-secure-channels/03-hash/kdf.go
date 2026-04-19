//go:build ignore

package main

import (
	"fmt"

	"golang.org/x/crypto/scrypt"
)

func main() {

	pw := []byte("some password")
	salt := []byte("some salt")

	dk, err := scrypt.Key(pw, salt, 32768, 8, 1, 32)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Derived key: %x", dk)
}
