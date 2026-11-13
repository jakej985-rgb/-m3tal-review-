package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// handle redeems the challenge twice — but handle is never called, so
// the challenge arrives as an unresolved parameter: the analysis can
// report the double consume only as a *potential* violation, never
// proven.
func handle(c *Challenge) {
	c.Consume()
	c.Consume()
}

func main() {}
