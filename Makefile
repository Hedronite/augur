# Augur build and gate. Run `make gate` before pushing.
GO       ?= go
GOBIN    := $(shell $(GO) env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

# Reproducible-build settings (see README and CI).
export CGO_ENABLED = 0
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
LDFLAGS := -s -w -buildid= -X github.com/Hedronite/augur/internal/cli.version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: gate build fmt-check tidy-check vet lint test race conformance vuln scrub secrets clean

gate: fmt-check tidy-check vet lint race conformance vuln scrub secrets ## everything CI runs, locally

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o augur ./cmd/augur

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

conformance:
	$(GO) test -count=1 -run 'Conform|Schema|Strict|Fixtures' ./internal/schema/...

vuln:
	govulncheck ./...

scrub:
	scripts/scrub.sh

secrets:
	gitleaks git --no-banner --redact .

clean:
	rm -f augur
