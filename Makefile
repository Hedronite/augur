# Augur build and gate. Run `make gate` before pushing.
GO       ?= go
GOBIN    := $(shell $(GO) env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

# Reproducible-build settings (see README and CI).
export CGO_ENABLED = 0
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
LDFLAGS := -s -w -buildid= -X github.com/Hedronite/augur/internal/cli.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: gate build release sbom release-check fmt-check tidy-check vet lint test race soak conformance vuln scrub scrub-selftest secrets clean

gate: fmt-check tidy-check vet lint race soak conformance vuln scrub scrub-selftest secrets ## everything CI runs, locally

build:
	$(GO) build -trimpath -buildvcs=false -ldflags '$(LDFLAGS)' -o augur ./cmd/augur

# VERSION is a tag such as v0.1.0; the archives and the binary's version use it as written.
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || echo v0.0.0-dev)

release: ## deterministic tarballs and SHA256SUMS in dist/ (needs only Go): make release VERSION=v0.1.0
	scripts/release.sh $(VERSION) dist

sbom: release ## CycloneDX SBOM per tarball, checked against its binary (needs cyclonedx-gomod, see docs/release.md)
	scripts/sbom.sh $(VERSION) dist

release-check: sbom ## everything the release workflow builds, plus a checksum verification
	cd dist && (sha256sum -c SHA256SUMS 2>/dev/null || shasum -a 256 -c SHA256SUMS)

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tidy-check:
	$(GO) mod tidy -diff

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race -count=1 ./...

soak: ## serve leak check: 1000 polls of 4000 alerts, no -race
	$(GO) test -count=1 -run '^TestSoak$$' ./internal/serve

conformance:
	$(GO) test -count=1 -run 'Conform|Schema|Strict|Fixtures|Vigil' ./internal/schema/... ./internal/vigilmap/...

vuln:
	govulncheck ./...

scrub:
	scripts/scrub.sh

scrub-selftest:
	scripts/scrub.sh --self-test

secrets:
	gitleaks git --no-banner --redact .

clean:
	rm -rf augur dist
