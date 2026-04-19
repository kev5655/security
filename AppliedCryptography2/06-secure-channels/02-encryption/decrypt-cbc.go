//go:build ignore

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	inputHex := "00000000000000000000000000000000536986a900afe6f01841904a7af50f95"
	inputData, err := hex.DecodeString(inputHex)
	if err != nil {
		log.Fatalf("Failed to decode hex input: %v\n", err)
	}

	if len(inputData) > 1024 {
		inputData = inputData[:1024]
	}

	if len(inputData) == 0 {
		return // Nothing to decrypt
	}

	// Skip the first 16 bytes (IV/prefix) to match the encryption output
	if len(inputData) <= aes.BlockSize {
		log.Fatalf("Input data too short to contain ciphertext after IV/prefix")
	}
	ciphertext := inputData[aes.BlockSize:]

	key := bytes.Repeat([]byte{'A'}, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher: %v\n", err)
	}
	ivLen := block.BlockSize()
	iv := bytes.Repeat([]byte{'X'}, ivLen)

	cbc := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	cbc.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS#7 padding
	paddingLen := int(plaintext[len(plaintext)-1])
	if paddingLen > 0 && paddingLen <= len(plaintext) {
		plaintext = plaintext[:len(plaintext)-paddingLen]
	}
	fmt.Println(string(plaintext))
}
