package main

// Token is a single-use credential.
type Token struct {
	used bool
}

// Consume marks the token as used. It performs no state check.
func (t *Token) Consume() {
	t.used = true
}

var current Token

func run() {
	current.Consume()
	current.Consume()
}

func main() { run() }
