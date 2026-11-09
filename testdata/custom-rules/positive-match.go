package main

import (
	"database/sql"
	"fmt"
	"log"
)

func run(db *sql.DB, input string) {
	authToken := "secret-token-123"
	log.Printf("Current session: %s", authToken)

	query := "SELECT * FROM users WHERE name = '" + input + "'"
	db.Query(query)
}
