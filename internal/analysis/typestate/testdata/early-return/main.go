package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// run consumes the challenge, then returns early on failure and
// consumes it again on the success path — the early return does not
// prevent the double consume on paths that continue.
func run(ok bool) {
	c := &Challenge{}
	c.Consume()
	if !ok {
		return
	}
	c.Consume()
}

func main() { run(true) }
