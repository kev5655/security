//go:build ignore

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"log"
	"os"
)

func main() {
	// 1. Read input from STDIN (Mimicking the C while(1) read loop)
	// io.ReadAll handles the loop automatically until EOF.
	// inputHex := "bcd99d247dd7ef2fd9b0f4d941c8148158470854efcd0cb5312fbdd1"
	inputHex := "bcd99d247dd7ef2fd9b0f4d9e1e218bfd9a2aaafde80c130f136af50"
	sign := "Here comes the signature"
	inputData := make([]byte, len(inputHex)/2)
	_, err := fmt.Sscanf(inputHex, "%x", &inputData)
	if err != nil {
		log.Fatalf("Failed to read input: %v\n", err)
	}

	// Mimicking the C code's 1024 byte buffer limit
	if len(inputData) > 1024 {
		inputData = inputData[:1024]
	}

	if len(inputData) == 0 {
		return // Nothing to decrypt
	}

	// 2. Setup Key & IV (Nonce) exactly as before
	key := bytes.Repeat([]byte{'A'}, 32)
	iv := bytes.Repeat([]byte{'X'}, 12)

	// 3. Initialize AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher: %v\n", err)
	}

	// 4. Initialize GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM: %v\n", err)
	}

	// 5. Decrypt the data
	// aesgcm.Open expects: (dst, nonce, ciphertext_with_tag, additionalData)
	// If the tag at the end of 'inputData' is missing or invalid, this returns an error.
	plaintext, err := aesgcm.Open(nil, iv, inputData, []byte(sign))
	if err != nil {
		log.Fatalf("Decryption failed (is the GCM tag missing or invalid?): %v\n", err)
	}

	// 6. Write plaintext to STDOUT
	if _, err := os.Stdout.Write(plaintext); err != nil {
		log.Fatalf("Failed to write output: %v\n", err)
	}
}
