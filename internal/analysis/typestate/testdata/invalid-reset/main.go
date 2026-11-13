package main

// Challenge is a single-use credential that can be re-armed.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// Reset re-arms a consumed challenge.
func (c *Challenge) Reset() {
	c.consumed = false
}

// run resets a challenge that was never consumed — an invalid reset.
func run() {
	c := &Challenge{}
	c.Reset()
}

func main() { run() }
