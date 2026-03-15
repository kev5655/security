package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/lib/pq"
)

const connStr = "postgres://inserter:inserter@localhost:5432/testdb?sslmode=disable"

func main() {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Use a command line argument as the message, or a default
	message := "Hello from the inserter!"
	if len(os.Args) > 1 {
		message = os.Args[1]
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop() // Good practice: clean up when the function ends

	for range ticker.C {
		// Insert the row
		currentVersion := getDBVersion(db)

		var newID int
		if currentVersion >= 2 {
			// V2 Logic: Inject the timestamp
			now := time.Now()
			err = db.QueryRow("INSERT INTO messages (content, created_at) VALUES ($1, $2) RETURNING id", message, now).Scan(&newID)
			if err == nil {
				fmt.Printf("[V2] Inserted row %d with timestamp %s\n", newID, now.Format(time.RFC3339))
			}
		} else {
			// V1 Logic: Standard insert
			err = db.QueryRow("INSERT INTO messages (content) VALUES ($1) RETURNING id", message).Scan(&newID)
			if err == nil {
				fmt.Printf("[V1] Inserted row %d without timestamp\n", newID)
			}
		}
	}

}

func getDBVersion(db *sql.DB) int {
	var version int
	// If this query fails (e.g., table doesn't exist yet), it returns an error,
	// and version remains 0. We will treat anything < 2 as Version 1.
	err := db.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version)
	if err != nil {
		return 1
	}
	return version
}
