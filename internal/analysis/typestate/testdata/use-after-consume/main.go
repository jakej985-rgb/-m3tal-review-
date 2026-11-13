package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// Check reads the challenge's validity without consuming it.
func (c *Challenge) Check() bool {
	return !c.consumed
}

// run consumes the challenge inside a conditional branch and then
// uses it after the merge: on the flag-true path the use is a
// use-after-consume violation.
func run(flag bool) {
	c := &Challenge{}
	if flag {
		c.Consume()
	}
	_ = c.Check()
}

func main() { run(true) }
