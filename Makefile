.PHONY: build test vet fmt bench bench-audit bench-jobs lint check release checksums sbom verify-reproducible clean

BUILD_FLAGS = -trimpath -ldflags="-s -w -buildid="

build:
	CGO_ENABLED=0 go build $(BUILD_FLAGS) ./...

test:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

bench:
	go test ./internal/review/ -run XXX -bench . -benchtime 1s

bench-audit:
	go test ./internal/benchmark/ -run XXX -bench BenchmarkAudit -benchmem

# Sweep audit --jobs settings (default, 1, 2, 4, half the cores) on a real repo and
# report wall time and peak CPU. Override with JOBS_SWEEP_REPS=5 JOBS_SWEEP_REPO=/path.
JOBS_SWEEP_REPS ?= 3
JOBS_SWEEP_REPO ?= .

bench-jobs:
	@./scripts/bench-jobs.sh "$(JOBS_SWEEP_REPO)" "$(JOBS_SWEEP_REPS)"

check: fmt vet build test

clean:
	rm -rf dist/

release: clean
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build $(BUILD_FLAGS) -o dist/m3tal-review-linux-amd64 ./cmd/m3tal-review
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build $(BUILD_FLAGS) -o dist/m3tal-review-linux-arm64 ./cmd/m3tal-review
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 \
		go build $(BUILD_FLAGS) -o dist/m3tal-review-darwin-amd64 ./cmd/m3tal-review
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
		go build $(BUILD_FLAGS) -o dist/m3tal-review-darwin-arm64 ./cmd/m3tal-review
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
		go build $(BUILD_FLAGS) -o dist/m3tal-review-windows-amd64.exe ./cmd/m3tal-review

checksums: release
	cd dist && sha256sum m3tal-review-* > checksums.txt

sbom:
	mkdir -p dist
	go list -m -json all > dist/sbom.json

verify-reproducible:
	@mkdir -p /tmp/m3tal-repro
	@CGO_ENABLED=0 go build $(BUILD_FLAGS) -o /tmp/m3tal-repro/b1 ./cmd/m3tal-review
	@CGO_ENABLED=0 go build $(BUILD_FLAGS) -o /tmp/m3tal-repro/b2 ./cmd/m3tal-review
	@H1=$$(sha256sum /tmp/m3tal-repro/b1 | cut -d' ' -f1); \
	H2=$$(sha256sum /tmp/m3tal-repro/b2 | cut -d' ' -f1); \
	rm -rf /tmp/m3tal-repro; \
	if [ "$$H1" = "$$H2" ]; then \
		echo "Reproducible build verified: SHA256 $$H1"; \
	else \
		echo "ERROR: Build hashes differ: $$H1 vs $$H2"; exit 1; \
	fi
