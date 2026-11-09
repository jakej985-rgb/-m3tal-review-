package main

import (
	"database/sql"
	"log"
)

func runSafe(db *sql.DB, input string) {
	log.Printf("Processing request")
	db.Query("SELECT * FROM users WHERE name = $1", input)
}
