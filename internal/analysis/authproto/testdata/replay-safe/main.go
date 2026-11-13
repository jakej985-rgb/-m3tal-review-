package main

import "crypto/rand"

// NewNonce generates a protocol nonce from the crypto/rand CSPRNG.
func NewNonce() ([16]byte, error) {
	var b [16]byte
	_, err := rand.Read(b[:])
	return b, err
}

func main() {}
