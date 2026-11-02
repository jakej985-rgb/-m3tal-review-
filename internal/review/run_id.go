package review

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func NewRunID() (string, error) {
	bytes := make([]byte, 8)

	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate run ID: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}
