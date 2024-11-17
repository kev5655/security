package main

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

const (
	workerCount  = 1
	payloadSize  = 16
	maxUintValue = 1 << 40
)

func main() {
	startTime := time.Now()
	targetHash := hash([]byte("Satoshi Nakamoto"))

	var result []byte
	var wg sync.WaitGroup

	rangeSize := uint64(maxUintValue / workerCount)

	fmt.Printf("%x, %d", rangeSize, rangeSize)

	for workerID := 0; workerID < workerCount; workerID++ {
		wg.Add(1)

		go func(workerID int) {
			defer wg.Done()

			start := uint64(workerID) * rangeSize
			end := start + rangeSize
			if workerID == workerCount-1 {
				end = maxUintValue
			}

			bruteforce := make([]byte, payloadSize)
			for i := start; i < end; i++ {
				fillPayload(bruteforce, i)

				h := hash(bruteforce)
				if h == targetHash {
					result = make([]byte, len(bruteforce))
					copy(result, bruteforce)
					endTime := time.Now()
					elapsed := endTime.Sub(startTime)
					fmt.Printf("Hash collision found!\n")
					fmt.Printf("\tTime taken: %s\n", elapsed)
					fmt.Printf("\tdata: hex: %x, str: %s\n", bruteforce, bruteforce)
					fmt.Printf("\tOriginal hash: %x\n", targetHash)
					fmt.Printf("\tCollision payload: %x\n", result)
				}
			}
		}(workerID)
	}

	wg.Wait()
	fmt.Println("DONE")
}

func hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func fillPayload(payload []byte, num uint64) {
	for i := len(payload) - 1; i >= 0; i-- {
		payload[i] = byte(num & 0xFF)
		num >>= 8
	}
}
