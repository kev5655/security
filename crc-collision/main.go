package main

import (
	"fmt"
	"hash/crc32"
)

func main() {
	payload := hash([]byte("Satoshi Nakamoto"))

	bruteforce := make([]byte, 16)

	for i := 0; i < len(bruteforce)-1; i++ {
		bruteforce[i] = 0
	}

	for true {
		incArray(bruteforce)
		h := hash(bruteforce)

		if h == payload {
			fmt.Printf("Hash collision found!\n")
			fmt.Printf("\tdata: hex: %x, str: %s\n", bruteforce, bruteforce)
			fmt.Printf("\tOriginal hash: %x\n", payload)
			fmt.Printf("\tCollision payload: %x\n\n\n", h)
		}
	}
}

func incArray(array []byte) {
	for i := len(array) - 1; i >= 0; i-- {
		array[i]++
		if array[i] != 0 {
			break
		}
	}
}

func hash(data []byte) uint32 {
	return crc32.Checksum(data, crc32.IEEETable)
}
