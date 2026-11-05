.PHONY: build test vet fmt bench lint check

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

bench:
	go test ./internal/review/ -run XXX -bench . -benchtime 1s

check: fmt vet build test
