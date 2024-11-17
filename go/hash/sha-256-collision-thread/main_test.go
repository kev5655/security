package main

import (
	"bytes"
	"fmt"
	"testing"
)

func TestGenRanges8_8(t *testing.T) {
	ranges := GenRanges(8, 8)

	for i := range ranges {
		fmt.Printf("%x\n", ranges[i])
	}

	expected := [][]byte{
		{0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x0, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0xff, 0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0, 0xff, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x0},
		{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff},
	}

	// Validate ranges against expected values
	for i := 0; i < len(expected); i++ {
		if !bytes.Equal(ranges[i], expected[i]) {
			t.Fatalf("Range %d mismatch: got %x, want %x", i, ranges[i], expected[i])
		}
	}
}

func TestGenRanges8_4(t *testing.T) {
	ranges := GenRanges(8, 4)

	for i := range ranges {
		fmt.Printf("%x\n", ranges[i])
	}

	expected := [][]byte{
		{0xff, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0xff, 0x0, 0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0, 0xff, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x0},
	}

	// Validate ranges against expected values
	for i := 0; i < len(expected); i++ {
		if !bytes.Equal(ranges[i], expected[i]) {
			t.Fatalf("Range %d mismatch: got %x, want %x", i, ranges[i], expected[i])
		}
	}
}

func TestGenRanges8_3(t *testing.T) {
	ranges := GenRanges(16, 6)

	for i := range ranges {
		fmt.Printf("%x\n", ranges[i])
	}

	expected := [][]byte{
		{0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfd, 0x00, 0x00},
	}

	// Validate ranges against expected values
	for i := 0; i < len(expected); i++ {
		if !bytes.Equal(ranges[i], expected[i]) {
			t.Fatalf("Range %d mismatch: got %x, want %x", i, ranges[i], expected[i])
		}
	}
}

func TestGenRangeAndShift(t *testing.T) {
	var size int = 4
	// fist := make([]byte, size)
	// rest := reverseSlice(GenRanges(size, 4))

	ranges := appendStartAndEnd(size, GenRanges(size, 4))

	for i := range ranges {
		fmt.Printf("%x\n", ranges[i])
	}

	expected := [][]byte{
		{0x0, 0x0, 0x0, 0x00},
		{0x0, 0x0, 0x0, 0xff},
		{0x0, 0x0, 0xff, 0x0},
		{0x0, 0xff, 0x0, 0x0},
		{0xff, 0x0, 0x0, 0x0},
	}

	// Validate ranges against expected values
	for i := 0; i < len(expected); i++ {
		if !bytes.Equal(ranges[i], expected[i]) {
			t.Fatalf("Range %d mismatch: got %x, want %x", i, ranges[i], expected[i])
		}
	}
}
