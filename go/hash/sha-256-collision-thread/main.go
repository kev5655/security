package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"
)

const (
	workerCount  = 20
	payloadSize  = 16
	maxUintValue = 1 << 40
)

func main() {
	startTime := time.Now()

	targetHash := hash([]byte("Satoshi Nakamoto"))

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
					// fmt.Printf("id: %d calc hash: %x\n", workerID, start)
					h := hash(start[:])
					if h == targetHash {
						var result [payloadSize]byte
						copy(result[:], start[:])
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

func splitRange(workerCount int) [][2][payloadSize]byte {
	totalRange := new(big.Int).Lsh(big.NewInt(1), payloadSize*8)
	// fmt.Printf("totalRange :%s\n", totalRange.Text(16))

	step := new(big.Int).Div(totalRange, big.NewInt(int64(workerCount)))
	// fmt.Printf("step: %s\n\n", step.Text(16))

	ranges := make([][2][payloadSize]byte, workerCount)

	for i := 0; i < workerCount; i++ {
		start := new(big.Int).Mul(step, big.NewInt(int64(i)))
		// fmt.Printf("start: %s bitlen: %d\n", start.Text(16), start.BitLen())
		end := new(big.Int).Mul(step, big.NewInt(int64(i+1)))
		// fmt.Printf("end:   %s bitlen: %d\n\n", end.Text(16), end.BitLen())

		var fixedStart [payloadSize]byte
		copy(fixedStart[:], start.Bytes())
		var fixedEnd [payloadSize]byte
		copy(fixedEnd[:], end.Bytes())

		ranges[i][0] = fixedStart
		ranges[i][1] = fixedEnd
	}

	return ranges
}

func intToBytes(num *big.Int, size int) [payloadSize]byte {
	var result [payloadSize]byte
	bytes := num.FillBytes(make([]byte, size))
	copy(result[:], bytes)
	return result
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

func hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// func GenRanges(size int, workerCount uint64) [][]byte {
// 	// Create a slice of slices (dynamic 2D array)
// 	ranges := make([][]byte, workerCount)

// 	for i := 0; i < int(workerCount); i++ {
// 		ranges[i] = make([]byte, size)
// 	}

// 	var index float64 = 0

// 	for i := 0; i < int(workerCount); i++ {
// 		quotient := float64(size) / float64(workerCount)
// 		_, div := math.Modf(index)
// 		// fmt.Printf("%d, %f, %f, %f\n", i, index, quotient, div)
// 		if div == 0 {
// 			ranges[int(i)][int(index)] = 255
// 		} else {
// 			ranges[int(i)][int(index)] = uint8(255 / div)
// 		}
// 		index += quotient
// 	}
// 	return ranges
// }

// func appendStartAndEnd(size int, ranges [][]byte) [][]byte {
// 	return append(
// 		append(
// 			[][]byte{make([]byte, size)},
// 			reverseSlice(ranges)...),
// 		genByteArray(size, 0xff))
// }

// func genByteArray(size int, value uint8) []byte {
// 	byteArray := make([]byte, size)
// 	for i := 0; i < size; i++ {
// 		byteArray[i] = value
// 	}
// 	return byteArray
// }

// func reverseSlice[T any](slice []T) []T {
// 	for i, j := 0, len(slice)-1; i < j; i, j = i+1, j-1 {
// 		slice[i], slice[j] = slice[j], slice[i]
// 	}
// 	return slice
// }
