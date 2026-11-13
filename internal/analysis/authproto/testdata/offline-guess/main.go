package main

import "crypto/sha256"

// passwordProof models a challenge/response where the client proves
// knowledge of a password by sending SHA-256(password || transcript).
// Anyone holding the transcript can test candidate passwords offline.
func passwordProof(password string, transcript []byte) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write(transcript)
	return h.Sum(nil)
}

func main() {}
