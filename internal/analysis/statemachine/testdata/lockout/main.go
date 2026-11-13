package main

// Guard implements a login lockout policy.
type Guard struct {
	attempts int
}

func (g *Guard) Attempt(now int64) {}
func (g *Guard) Unlock(now int64)  {}
func (g *Guard) Success()          {}

var g Guard

func run() {
	g.Attempt(1)
	g.Attempt(2)
	g.Attempt(3)
	g.Attempt(4) // exceeds max_attempts: locks until now+60
	g.Attempt(5) // illegal: still locked
	g.Unlock(100)
	g.Attempt(6)
	g.Success()
}

func main() { run() }
