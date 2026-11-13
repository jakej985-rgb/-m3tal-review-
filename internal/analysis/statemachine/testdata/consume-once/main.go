package main

type Token struct {
	used bool
}

func (t *Token) Consume() {
	t.used = true
}

var current Token

func run() {
	current.Consume()
}

func main() { run() }
