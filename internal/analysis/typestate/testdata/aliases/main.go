package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// run redeems a challenge through an alias: alias and c denote the
// same resource, so the second consume must be flagged.
func run() {
	c := &Challenge{}
	alias := c
	alias.Consume()
	c.Consume()
}

func main() { run() }
