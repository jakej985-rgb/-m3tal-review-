package main

import (
	"math/rand"
	"time"
)

func init() { rand.Seed(time.Now().UnixNano()) }

// NewNonce is bound by the contract as the client's nonce source. It
// reaches math/rand through a helper, exercising transitive scanning.
func NewNonce() int64 {
	return next()
}

func next() int64 { return rand.Int63() }

func main() {}
