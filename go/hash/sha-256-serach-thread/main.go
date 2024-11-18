package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

const (
	workerCount  = 2
	size         = 8
	targetPrefix = "0000000"
	transaction  = "Alice,Bob,$100"
)

func main() {
	startTime := time.Now()

	var wg sync.WaitGroup

	ranges := splitRange(workerCount)

	fmt.Println("All Ranges:")
	for i := range ranges {
		fmt.Printf("%d: start   %x\n", i, ranges[i][0])
		fmt.Printf("%d: end     %x\n\n", i, ranges[i][1])
	}

	for workerID := 0; workerID < workerCount; workerID++ {
		wg.Add(1)

		go func(workerID int) {
			defer wg.Done()

			start := ranges[workerID][0][:]
			end := ranges[workerID][1][:]

			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					fmt.Printf("Thread %d: Current addr: %x End range: %x\n", workerID, start, end)
				default:
					start, endReached := incArray(start, end)
					input := append([]byte(transaction), start...)
					// input := fmt.Sprintf("%s%s", transaction, start)
					// fmt.Printf("id: %d calc hash: %x\n", workerID, start)
					h := hash(input)
					if strings.HasPrefix(h, targetPrefix) {
						endTime := time.Now()
						elapsed := endTime.Sub(startTime)

						fmt.Printf("Hash found with 7 zeros!\n")
						fmt.Printf("\tTime taken: %s\n", elapsed)
						fmt.Printf("\thash input as string: %s input: as hex %x hash output: %s\n\n", input, input, h)
					}

					if endReached {
						return
					}
				}
			}
		}(workerID)
	}

	wg.Wait()
	fmt.Println("DONE")
}

func splitRange(workerCount int) [][2][size]byte {
	totalRange := new(big.Int).Lsh(big.NewInt(1), size*8)
	// fmt.Printf("totalRange :%s\n", totalRange.Text(16))

	step := new(big.Int).Div(totalRange, big.NewInt(int64(workerCount)))
	// fmt.Printf("step: %s\n\n", step.Text(16))

	ranges := make([][2][size]byte, workerCount)

	for i := 0; i < workerCount; i++ {
		start := new(big.Int).Mul(step, big.NewInt(int64(i)))
		// fmt.Printf("start: %s bitlen: %d\n", start.Text(16), start.BitLen())
		end := new(big.Int).Mul(step, big.NewInt(int64(i+1)))
		// fmt.Printf("end:   %s bitlen: %d\n\n", end.Text(16), end.BitLen())

		var fixedStart [size]byte
		copy(fixedStart[:], start.Bytes())
		var fixedEnd [size]byte
		copy(fixedEnd[:], end.Bytes())

		ranges[i][0] = fixedStart
		ranges[i][1] = fixedEnd
	}

	return ranges
}

func incArray(array []byte, max []byte) ([]byte, bool) {
	for i := len(array) - 1; i >= 0; i-- {
		array[i]++
		if array[i] != 0 {
			break
		}

		if bytes.Equal(array, max) {
			return array, true
		}
	}
	return array, false
}

func hash(data []byte) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
