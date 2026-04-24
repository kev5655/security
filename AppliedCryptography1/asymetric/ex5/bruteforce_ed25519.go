package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
	"unicode/utf8"
)

func toFixedBytes(v uint64, size int) []byte {
	out := make([]byte, size)
	for i := size - 1; i >= 0; i-- {
		out[i] = byte(v)
		v >>= 8
	}
	return out
}

func main() {
	m := []byte("Hey")
	fmt.Printf("Message Bits %d\n", len(m))

	if len(m)*8 >= 64 {
		fmt.Println("Message too long for this uint64 brute-force demo")
		return
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	signature := ed25519.Sign(privateKey, m)

	totalIterations := uint64(1) << uint(len(m)*8)
	fmt.Printf("This is the range: %d\n", totalIterations)

	startTime := time.Now()
	fmt.Printf("Loop started at: %s\n", startTime.Format("2006-01-02 15:04:05"))

	for i := uint64(0); i < totalIterations; i++ {
		candidate := toFixedBytes(i, len(m))
		if ed25519.Verify(publicKey, candidate, signature) {
			if utf8.Valid(candidate) {
				fmt.Printf("The message is: %s\n", string(candidate))
			} else {
				fmt.Printf("The message bytes (hex): %s\n", hex.EncodeToString(candidate))
			}
			break
		}

		if i > 0 && i%100000 == 0 {
			now := time.Now()
			elapsed := now.Sub(startTime).Seconds()
			rate := float64(i) / elapsed

			if rate > 0 {
				remainingSeconds := float64(totalIterations-i) / rate
				eta := now.Add(time.Duration(remainingSeconds * float64(time.Second)))
				fmt.Printf(
					"Now: %s | Expected finish: %s | Elapsed: %.1fs | Remaining: %.1fs\n",
					now.Format("15:04:05"),
					eta.Format("15:04:05"),
					elapsed,
					remainingSeconds,
				)
			} else {
				fmt.Printf("Now: %s | Expected finish: calculating...\n", now.Format("15:04:05"))
			}
		}
	}
}
