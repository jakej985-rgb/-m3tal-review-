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

// checkFactor is a helper that redeems the challenge during the
// first-factor check.
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

// handleAuth is the dual-auth handler: it redeems the same challenge
// once while checking the first factor and again while checking the
// second — two consumes of one challenge on a single request path.
func handleAuth(user, pass string) bool {
	c := &Challenge{nonce: user + ":" + pass}
	if user == "" || pass == "" {
		return false // early return before any consume
	}
	first := checkFactor(c)
	second := checkSecondFactor(c)
	return first && second
}

func main() {
	_ = handleAuth("admin", "s3cret")
}
