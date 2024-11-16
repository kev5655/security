package main

import (
	"fmt"
	"hash/crc32"
	"log"
	"os"
	"testing"
)

func main() {

}

func checksum(body []byte) string {
	checksum_int := crc32.Checksum(body, crc32.IEEETable)
	return fmt.Sprintf("%x", checksum_int)
}

func read_file() []byte {
	body, err := os.ReadFile("500kbFile")
	if err != nil {
		log.Fatalf("unable to read file: %v", err)
	}
	return body
}

func BenchmarkFunc(b *testing.B) {
	file := read_file()
	for i := 0; i < b.N; i++ {
		checksum(file)
	}
}
