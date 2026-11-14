package main

// Challenge is a single-use authentication challenge (nonce). It may
// be redeemed exactly once; Consume performs no state check.
type Challenge struct {
	nonce    string
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// checkFactor redeems the challenge during the first-factor check.
func checkFactor(c *Challenge) bool {
	c.Consume()
	return true
}

// checkSecondFactor redeems the challenge again during the
// second-factor check.
func checkSecondFactor(c *Challenge) bool {
	c.Consume()
	return c.consumed
}

// handleAuth redeems the same challenge once per factor check on a
// single request path — a double consume the typestate contract
// should flag.
func handleAuth(user, pass string) bool {
	c := &Challenge{nonce: user + ":" + pass}
	if user == "" || pass == "" {
		return false
	}
	first := checkFactor(c)
	second := checkSecondFactor(c)
	return first && second
}

func main() {
	_ = handleAuth("admin", "s3cret")
}
