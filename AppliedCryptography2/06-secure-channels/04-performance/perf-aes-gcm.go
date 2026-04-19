//go:build ignore

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"log"
	"time"
)

var (
	AES256_KEY_SIZE_BYTES = 32
	IV_SIZE_BIT_FAST      = 96 // https://crypto.stackexchange.com/questions/41601/aes-gcm-recommended-iv-size-why-12-bytes
	IV_SIZE_BIT_SLOW      = 128
)

type EncDec struct {
	plaintext []byte
	key       []byte
	iv        []byte
	sign      string
}

func main() {

	// for range 10 {
	data := generateTestData(730) // 730 iterations * 1 MB = 730 MB of data to encrypt and decrypt
	start := time.Now()
	encAndDec(data)
	log.Printf("encAndDec took %v\n", time.Since(start))
	// }

}

func generateTestData(itterations int) []EncDec {

	data := make([]EncDec, 0, itterations)

	for range itterations {
		payload := generateTestPlainText(1_000_000) // 1 MB of data
		key := make([]byte, AES256_KEY_SIZE_BYTES)
		_, err := rand.Read(key)
		if err != nil {
			log.Fatalf("Failed to generate random key: %v\n", err)
		}

		iv := make([]byte, IV_SIZE_BIT_SLOW/8)
		_, err = rand.Read(iv)
		if err != nil {
			log.Fatalf("Failed to generate random IV: %v\n", err)
		}
		sign := "Here comes the signature"

		data = append(data, EncDec{
			plaintext: payload,
			key:       key,
			iv:        iv,
			sign:      sign,
		})
	}

	// for i := range data {
	// 	for j := range data[i].plaintext {
	// 		_ = data[i].plaintext[j]
	// 	}
	// }

	return data
}

func encAndDec(data []EncDec) {

	for _, d := range data {
		// fmt.Printf("key: %x, iv: %x, sign: %s\n", d.key, d.iv, d.sign)
		cipherText, _, _ := decrypt(d.plaintext, d.key, d.iv, d.sign)
		encrypt(cipherText, d.key, d.iv, d.sign)
	}
}

func generateTestPlainText(n int) []byte {
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		log.Fatalf("Failed to generate random plaintext: %v\n", err)
	}
	return data
}

func decrypt(plaintext []byte, key []byte, iv []byte, sign string) ([]byte, []byte, []byte) {

	inputValidateion(plaintext, key)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher: %v\n", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM: %v\n", err)
	}

	if len(iv) != aesgcm.NonceSize() {
		// log.Printf("WARN: IV length must be %d bytes\n", aesgcm.NonceSize())
		aesgcm, err = cipher.NewGCMWithNonceSize(block, len(iv))
		if err != nil {
			log.Fatalf("Error creating GCM: %v\n", err)
		}
	}

	ciphertextWithTag := aesgcm.Seal(nil, iv, plaintext, []byte(sign))

	exactCiphertext := ciphertextWithTag[:len(plaintext)]
	tag := ciphertextWithTag[len(plaintext):]

	return ciphertextWithTag, exactCiphertext, tag
}

func encrypt(cipherText []byte, key []byte, iv []byte, sign string) {

	inputValidateion(cipherText, key)

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalf("Error creating cipher: %v\n", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatalf("Error creating GCM: %v\n", err)
	}

	if len(iv) != aesgcm.NonceSize() {
		// log.Printf("WARN: IV length must be %d bytes\n", aesgcm.NonceSize())
		aesgcm, err = cipher.NewGCMWithNonceSize(block, len(iv))
		if err != nil {
			log.Fatalf("Error creating GCM: %v\n", err)
		}
	}

	_, err = aesgcm.Open(nil, iv, cipherText, []byte(sign))
	if err != nil {
		log.Fatalf("Decryption failed (is the GCM tag missing or invalid?): %v\n", err)
	}
}

func inputValidateion(data, key []byte) {
	if len(key) != AES256_KEY_SIZE_BYTES {
		log.Fatalf("Key must be %d bytes for AES-256, it is: %d\n", AES256_KEY_SIZE_BYTES, len(key))
	}

	if len(data) == 0 {
		log.Fatalf("Data cannot be empty\n")
	}
}
