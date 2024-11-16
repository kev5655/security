package main

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

const (
	workerCount  = 6       // Number of threads/workers
	payloadSize  = 16      // Size of the brute force payload in bytes
	maxUintValue = 1 << 40 // Maximum range for brute force (adjust as needed)
)

func main() {
	// Target hash for "Satoshi Nakamoto"
	targetHash := hash([]byte("Satoshi Nakamoto"))

	var result []byte
	var wg sync.WaitGroup

	// Calculate range per worker
	rangeSize := uint64(maxUintValue / workerCount)

	// Start workers
	for workerID := 0; workerID < workerCount; workerID++ {
		wg.Add(1)

		go func(workerID int) {
			defer wg.Done()

			// Calculate range for this worker
			start := uint64(workerID) * rangeSize
			end := start + rangeSize
			if workerID == workerCount-1 {
				end = maxUintValue // Ensure last worker covers the full range
			}

			// Perform brute force in the assigned range
			bruteforce := make([]byte, payloadSize)
			for i := start; i < end; i++ {
				fillPayload(bruteforce, i)

				// Check hash
				h := hash(bruteforce)
				if h == targetHash {
					result = make([]byte, len(bruteforce))
					copy(result, bruteforce)
					fmt.Printf("Hash collision found!\n")
					fmt.Printf("\tdata: hex: %x, str: %s\n", bruteforce, bruteforce)
					fmt.Printf("\tOriginal hash: %x\n", targetHash)
					fmt.Printf("\tCollision payload: %x\n", result)
				}
			}
		}(workerID)
	}

	// Wait for all workers to finish
	wg.Wait()
	fmt.Println("DONE")
}

// hash calculates the CRC32 checksum for the given data
func hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// fillPayload fills the payload based on the current number (big-endian representation)
func fillPayload(payload []byte, num uint64) {
	for i := len(payload) - 1; i >= 0; i-- {
		payload[i] = byte(num & 0xFF)
		num >>= 8
	}
}
