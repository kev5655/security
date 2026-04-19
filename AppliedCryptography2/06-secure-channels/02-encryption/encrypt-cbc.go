//go:build ignore

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
)

func main() {
	plaintext := []byte("Hello world")

	key := bytes.Repeat([]byte{'A'}, 32) // 256 Bit

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher: %v\n", err)
	}

	ivLen := block.BlockSize()
	iv := bytes.Repeat([]byte{'X'}, ivLen) // IV must have the same length as the block size for CBC mode

	// PKCS#7 padding
	padding := ivLen - (len(plaintext) % ivLen)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	plaintextPadded := append(plaintext, padtext...)

	cbc := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, aes.BlockSize+len(plaintextPadded))
	cbc.CryptBlocks(ciphertext[aes.BlockSize:], plaintextPadded)

	for _, b := range ciphertext {
		fmt.Printf("%02x", b)
	}
	fmt.Println()
}
