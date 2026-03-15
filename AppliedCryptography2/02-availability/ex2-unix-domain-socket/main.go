package main

import (
	"fmt"
	"net/http"
	"os"
)

func rand(w http.ResponseWriter, req *http.Request) {
	// 1. Open the device file just like a normal file
	file, err := os.Open("/dev/random")
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to open /dev/random: %v", err), http.StatusInternalServerError)
		return
	}
	// Always remember to close file handles when done!
	defer file.Close()

	// 2. Create a buffer (a temporary container) to hold the bytes we read
	// Let's grab 16 bytes of random data
	buf := make([]byte, 64)

	// 3. Read the random bytes from the file into our buffer
	n, err := file.Read(buf)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read from file: %v", err), http.StatusInternalServerError)
		return
	}

	// 4. Send the result back to the user.
	// We use %x to format the raw bytes as a readable hexadecimal string.
	fmt.Fprintf(w, "Successfully read %d bytes from /dev/random:\n%x\n", n, buf)
}

func main() {

	http.HandleFunc("/random", rand)

	http.ListenAndServe(":8090", nil)
}
