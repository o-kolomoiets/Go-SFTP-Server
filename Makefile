GO            ?= go
GOLANGCI_LINT ?= golangci-lint
TOOL          := $(GO) tool -modfile=tools/go.mod

.PHONY: all build test interop lint fmt tidy vuln staticcheck clean

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

vuln: ## Scan for known vulnerabilities
	$(TOOL) govulncheck ./...

staticcheck: ## Run staticcheck standalone (also runs inside golangci-lint)
	$(TOOL) staticcheck ./...

clean:
	rm -rf bin/ dist/ out/ coverage/
