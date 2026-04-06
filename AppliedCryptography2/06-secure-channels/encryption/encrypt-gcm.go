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
	// 1. Setup Plaintext (include null terminator to match C's sizeof("Hello world"))
	plaintext := append([]byte("Hello world"), 0)

	// 2. Setup Key: 256 bits = 32 bytes of 'A'
	key := bytes.Repeat([]byte{'A'}, 32)

	// 3. Setup IV (Nonce): 96 bits = 12 bytes of 'X'
	iv := bytes.Repeat([]byte{'X'}, 12)

	// 4. Initialize AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher: %v\n", err)
	}

	// 5. Wrap the cipher block in GCM mode
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM: %v\n", err)
	}

	// 6. Encrypt the data
	// Go's Seal function takes (dst, nonce, plaintext, additionalData)
	// It appends the ciphertext AND the 16-byte authentication tag to dst.
	ciphertextWithTag := aesgcm.Seal(nil, iv, plaintext, nil)

	for _, b := range ciphertextWithTag {
		fmt.Printf("%02x", b)
	}
	fmt.Println()

	// 7. Write to STDOUT
	// To match the C code's exact output (which ignores the GCM tag),
	// we slice the byte array to only output the encrypted plaintext.
	exactCiphertext := ciphertextWithTag[:len(plaintext)]
	fmt.Printf("Ciphertext: %x\n", exactCiphertext)
	tag := ciphertextWithTag[len(plaintext):]
	fmt.Printf("GCM Tag: %x\n", tag)
}
