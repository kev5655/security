package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/lib/pq"
)

const connStr = "postgres://listen:listen@localhost:9999/testdb?sslmode=disable"

func main() {
	// 1. Connect to the database for standard queries
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var lastSeenID int

	// 2. Fetch and print existing rows on startup
	rows, err := db.Query("SELECT id, content FROM messages ORDER BY id ASC")
	if err == nil {
		fmt.Println("--- Existing Rows ---")
		for rows.Next() {
			var content string
			rows.Scan(&lastSeenID, &content)
			fmt.Printf("ID: %d | Content: %s\n", lastSeenID, content)
		}
		rows.Close()
	}

	// 3. Set up the Listener
	reportErr := func(ev pq.ListenerEventType, err error) {
		if err != nil {
			fmt.Println("Listener error:", err)
		}
	}
	listener := pq.NewListener(connStr, 10*time.Second, time.Minute, reportErr)
	err = listener.Listen("new_message_channel")
	if err != nil {
		log.Fatal("Could not listen:", err)
	}

	fmt.Println("\n--- Waiting for new rows (No busy-waiting!) ---")

	// 4. Wait for notifications
	for {
		select {
		case <-listener.Notify:
			currentVersion := getDBVersion(db)

			if currentVersion >= 2 {
				// V2 Logic: Select and scan the new created_at column
				newRows, _ := db.Query("SELECT id, content, created_at FROM messages WHERE id > $1 ORDER BY id ASC", lastSeenID)
				for newRows.Next() {
					var content string
					var createdAt time.Time
					newRows.Scan(&lastSeenID, &content, &createdAt)
					fmt.Printf("[V2 LISTENER] ID: %d | Content: %s | Time: %s\n", lastSeenID, content, createdAt.Format(time.Kitchen))
				}
				newRows.Close()
			} else {
				// V1 Logic: Standard select
				newRows, _ := db.Query("SELECT id, content FROM messages WHERE id > $1 ORDER BY id ASC", lastSeenID)
				for newRows.Next() {
					var content string
					newRows.Scan(&lastSeenID, &content)
					fmt.Printf("[V1 LISTENER] ID: %d | Content: %s\n", lastSeenID, content)
				}
				newRows.Close()
			}

		case <-time.After(90 * time.Second):
			// Optional: Periodically ping the connection to keep it alive
			go listener.Ping()
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
