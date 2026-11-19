# Releasing m3tal-review

## 1. Versioning & Tags

`m3tal-review` follows Semantic Versioning (`vMAJOR.MINOR.PATCH`).
- Releases are annotated git tags in the format `vX.Y.Z` (e.g. `v1.0.0`).
- Report schema compatibility guarantees are documented in `docs/report-schema-policy.md`.
- Breaking changes require a major version bump.

---

## 2. Reproducible Builds & Cross-Platform Matrix

Release binaries are built as statically linked Go binaries with deterministic build flags:
```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" ./cmd/m3tal-review
```
Flags:
- `-trimpath`: Strips absolute file system paths from stack traces and binaries.
- `-ldflags="-s -w -buildid="`: Strips debugging symbols, DWARF tables, and non-deterministic
  Go build IDs to guarantee bit-for-bit reproducibility.

### Supported Target Matrix:
- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`

Run `make release` to generate binaries in `dist/`.

---

## 3. Checksums & SBOM (Software Bill of Materials)

1. **SHA-256 Checksums**:
   Generate checksums for all release binaries:
   ```bash
   make checksums
   ```
   This generates `dist/checksums.txt`. Consumers can verify artifact integrity with:
   ```bash
   sha256sum -c checksums.txt
   ```

2. **SBOM Generation**:
   Generate machine-readable module dependency manifests:
   ```bash
   make sbom
   ```
   Produces `dist/sbom.json` documenting all transitive Go module dependencies and hashes.

3. **Reproducibility Verification**:
   Verify that consecutive builds produce identical cryptographic digests:
   ```bash
   make verify-reproducible
   ```

---

## 4. Pre-Release Verification Gates

Before tagging a release, all quality and security gates must pass:

```bash
make check                  # gofmt, go vet, build, unit tests
make verify-reproducible    # bit-for-bit build reproducibility
go test -race ./...         # full race-detector suite across packages
```

Ensure all report schema compatibility tests pass:
```bash
go test -v -race ./internal/review -run TestReportSchemaCompatibility
```

---

## 5. Tagging & Publishing

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```
Notice: `m3tal-review` is local-first and does not upload artifacts or metrics to third-party
services unless explicitly configured with `--check-run` or `--pr-comment`.
