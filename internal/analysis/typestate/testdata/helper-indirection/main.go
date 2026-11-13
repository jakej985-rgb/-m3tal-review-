package main

// Challenge is a single-use credential.
type Challenge struct {
	consumed bool
}

// Consume redeems the challenge's single use.
func (c *Challenge) Consume() {
	c.consumed = true
}

// redeemViaAuditLog consumes the challenge from inside an audit
// helper.
func redeemViaAuditLog(c *Challenge) {
	c.Consume()
}

// redeemViaMetrics consumes the challenge from inside a metrics
// helper.
func redeemViaMetrics(c *Challenge) {
	c.Consume()
}

// handle redeems the same challenge through two different helper
// functions — helper indirection must not hide the second consume.
func handle(c *Challenge) {
	redeemViaAuditLog(c)
	redeemViaMetrics(c)
}

func main() {
	c := &Challenge{}
	handle(c)
}
