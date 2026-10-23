GO            ?= go
GOLANGCI_LINT ?= golangci-lint
TOOL          := $(GO) tool -modfile=tools/go.mod

.PHONY: all build test interop lint fmt tidy vuln staticcheck generate clean

all: lint test build

build: ## Build bin/gosftpd
	$(GO) build -trimpath -o bin/gosftpd ./cmd/gosftpd

test: ## Run unit tests with the race detector
	$(GO) test -race -shuffle=on -count=1 ./...

interop: ## OpenSSH sftp/scp/ssh against a fresh build
	test/interop/run.sh

lint: ## gofmt, go vet, golangci-lint, actionlint
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "$$unformatted"; exit 1; fi
	$(GO) vet ./...
	$(GOLANGCI_LINT) run ./...
	$(TOOL) actionlint

fmt: ## Apply gofumpt and goimports
	$(GOLANGCI_LINT) fmt ./...

tidy: ## Tidy both modules
	$(GO) mod tidy
	cd tools && $(GO) mod tidy

vuln: ## Scan both modules for known vulnerabilities
	$(TOOL) govulncheck ./...
	cd tools && $(GO) tool govulncheck tool

staticcheck: ## Run staticcheck standalone (also runs inside golangci-lint)
	$(TOOL) staticcheck ./...

# The files a release adds to the binary, into out/ (ignored by git): the
# GoReleaser before hook and the release's generate job run this (ADR 0012).
# SOURCE_DATE_EPOCH, the commit time, dates the man pages.
generate: ## Man pages, completions and the image's empty directories into out/
	SOURCE_DATE_EPOCH="$$(git log -1 --format=%ct)" $(GO) generate ./...
	mkdir -p out/docker/empty out/docker/home-root/home

clean:
	rm -rf bin/ dist/ out/ coverage/
