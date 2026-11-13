package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// run redeems two DISTINCT challenges once each — legal, must not be
// flagged as double consumption.
func run() {
	first := &Challenge{}
	second := &Challenge{}
	first.Consume()
	second.Consume()
}

func main() { run() }
