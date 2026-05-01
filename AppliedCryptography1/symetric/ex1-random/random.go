package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"
)

func main() {
	bitMap := make(map[int]int64, 1_000_000)
	last := time.Now()

	oneMilliSecond := 1000
	oneSec := oneMilliSecond * 1000
	iterations := oneSec * 60 * 2
	fmt.Println("Collecting data...")

	for range iterations {
		time.Sleep(time.Nanosecond * 1)
		now := time.Now()
		bitMap[int(now.Sub(last).Nanoseconds())]++
		last = now
	}

	// Clean up the map by removing all entries with a count of 1
	for latency, count := range bitMap {
		if count == 1 {
			delete(bitMap, latency)
		}
	}

	fmt.Println("Saving to CSV...")

	file, err := os.Create("latency_data.csv")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	writer.Write([]string{"Latency_ns", "Count"})

	// --- NEW SORTING LOGIC ---

	// 1. Create a slice to hold all your Latency_ns keys
	keys := make([]int, 0, len(bitMap))
	for latency := range bitMap {
		keys = append(keys, latency)
	}

	// 2. Sort the slice from lowest to highest
	sort.Ints(keys)

	// 3. Loop through your SORTED keys, and grab the counts from the map
	for _, latency := range keys {
		count := bitMap[latency] // Pull the value using the sorted key

		row := []string{
			strconv.Itoa(latency),
			strconv.FormatInt(count, 10),
		}
		writer.Write(row)
	}

	fmt.Println("Done! Data saved and sorted in latency_data.csv")
}
