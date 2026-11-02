package review

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

func NewRunID() (string, error) {
	bytes := make([]byte, 8)

	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate run ID: %w", err)
	}

	return hex.EncodeToString(bytes), nil
}

func IsValidRunID(runID string) bool {
	if len(runID) != 16 {
		return false
	}

	_, err := hex.DecodeString(runID)
	if err != nil {
		return false
	}

	return strings.ToLower(runID) == runID
}
