package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// run consumes the challenge on exactly one side of each branch —
// every path consumes it once, so no violation may be reported.
func run(flag bool) {
	c := &Challenge{}
	if flag {
		c.Consume()
	} else {
		c.Consume()
	}
}

func main() { run(true) }
