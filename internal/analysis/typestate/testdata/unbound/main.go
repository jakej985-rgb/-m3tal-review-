package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use. The typestate spec does
// NOT bind this function — names alone carry no semantics, so calling
// it twice must produce no findings.
func (c *Challenge) Consume() {
	c.consumed = true
}

func run() {
	c := &Challenge{}
	c.Consume()
	c.Consume()
}

func main() { run() }
