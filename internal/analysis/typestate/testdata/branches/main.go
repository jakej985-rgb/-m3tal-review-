package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// run consumes the challenge inside a conditional branch and then
// again after the merge: on the flag-true path the challenge is
// consumed twice.
func run(flag bool) {
	c := &Challenge{}
	if flag {
		c.Consume()
	}
	c.Consume()
}

func main() { run(true) }
