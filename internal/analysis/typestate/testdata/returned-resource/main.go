package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

var pool Challenge

// issue returns the shared challenge. The analysis cannot always track
// identity through call results, so findings on the returned resource
// may be reported as potential rather than proven.
func issue() *Challenge {
	return &pool
}

func run() {
	c := issue()
	c.Consume()
	c.Consume()
}

func main() { run() }
