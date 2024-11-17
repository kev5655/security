package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"sync"
	"time"
)

const (
	workerCount  = 16
	payloadSize  = 16
	maxUintValue = 1 << 40
)

func main() {
	startTime := time.Now()
	targetHash := hash([]byte("Satoshi Nakamoto"))

	var result []byte
	var wg sync.WaitGroup

	ranges := appendStartAndEnd(payloadSize, GenRanges(payloadSize, workerCount))

	fmt.Println("All Ranges:")
	for i := range ranges {
		fmt.Printf("%x\n", ranges[i])
	}

	for workerID := 0; workerID < workerCount; workerID++ {
		wg.Add(1)

		go func(workerID int) {
			defer wg.Done()

			refStart := ranges[workerID]
			start := make([]byte, len(refStart))
			copy(start, refStart)

			refEnd := ranges[workerID+1]
			end := make([]byte, len(refEnd))
			copy(end, refEnd)

			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					fmt.Printf("Thread %d: Current addr: %x End range: %x\n", workerID, start, end)
				default:
					endReached := incArray(start, end)

					h := hash(start)
					if h == targetHash {
						result = make([]byte, len(start))
						copy(result, start)
						endTime := time.Now()
						elapsed := endTime.Sub(startTime)
						fmt.Printf("Hash collision found!\n")
						fmt.Printf("\tTime taken: %s\n", elapsed)
						fmt.Printf("\tdata: hex: %x, str: %s\n", start, start)
						fmt.Printf("\tOriginal hash: %x\n", targetHash)
						fmt.Printf("\tCollision payload: %x\n", result)
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

func GenRanges(size int, workerCount uint64) [][]byte {
	// Create a slice of slices (dynamic 2D array)
	ranges := make([][]byte, workerCount)

	for i := 0; i < int(workerCount); i++ {
		ranges[i] = make([]byte, size)
	}

	var index float64 = 0

	for i := 0; i < int(workerCount); i++ {
		quotient := float64(size) / float64(workerCount)
		_, div := math.Modf(index)
		// fmt.Printf("%d, %f, %f, %f\n", i, index, quotient, div)
		if div == 0 {
			ranges[int(i)][int(index)] = 255
		} else {
			ranges[int(i)][int(index)] = uint8(255 / div)
		}
		index += quotient
	}
	return ranges
}

func appendStartAndEnd(size int, ranges [][]byte) [][]byte {
	return append(
		append(
			[][]byte{make([]byte, size)},
			reverseSlice(ranges)...),
		genByteArray(size, 0xff))
}

func genByteArray(size int, value uint8) []byte {
	byteArray := make([]byte, size)
	for i := 0; i < size; i++ {
		byteArray[i] = value
	}
	return byteArray
}

func hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func incArray(array []byte, max []byte) bool {
	for i := len(array) - 1; i >= 0; i-- {
		array[i]++
		if array[i] != 0 {
			break
		}

		if bytes.Equal(array, max) {
			return true
		}
	}
	return false
}

func reverseSlice[T any](slice []T) []T {
	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
		slice[i], slice[j] = slice[j], slice[i]
	}
	return slice
}
