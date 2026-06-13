# Anubis Security Scanner — Makefile
# Requires Go 1.21+

BINARY   := anubis
MAIN_PKG := ./cmd/anubis
VERSION  := 1.0.0
LDFLAGS  := -ldflags "-X main.Version=$(VERSION) -s -w"

.PHONY: all build install clean run help deps lint

## Default: build for current platform
all: deps build

## Download dependencies
deps:
	go mod download
	go mod tidy

## Build binary in current directory
build:
	go build $(LDFLAGS) -o $(BINARY) $(MAIN_PKG)
	@echo "[+] Built: ./$(BINARY)"

## Install to GOPATH/bin
install:
	go install $(LDFLAGS) $(MAIN_PKG)
	@echo "[+] Installed: $$(go env GOPATH)/bin/$(BINARY)"

## Cross-compile for common targets
build-all:
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64   $(MAIN_PKG)
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64   $(MAIN_PKG)
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-windows.exe   $(MAIN_PKG)
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64  $(MAIN_PKG)
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64  $(MAIN_PKG)
	@echo "[+] Cross-compiled to dist/"

## Remove built binaries
clean:
	rm -f $(BINARY)
	rm -rf dist/

## Quick Level 1 scan example (replace TARGET)
run:
	./$(BINARY) -t http://$(TARGET) -l 1 -v

## Run tests
test:
	go test ./...

## Lint (requires golangci-lint)
lint:
	golangci-lint run ./...

## Show help
help:
	@echo "Usage:"
	@echo "  make deps    — download Go modules"
	@echo "  make build   — build ./anubis binary"
	@echo "  make install — install to GOPATH/bin"
	@echo "  make build-all — cross-compile for all platforms"
	@echo "  make clean   — remove built binaries"
	@echo "  make run TARGET=example.com — quick Level 1 scan"
	@echo ""
	@echo "After building:"
	@echo "  ./anubis -t https://example.com -l 1"
	@echo "  ./anubis -t https://example.com -l 2 --format html+json -o myreport"
	@echo "  ./anubis -t https://example.com -l 3 --threads 10 --deep-scan"
	@echo "  ./anubis --resume"
	@echo "  ./anubis --batch --batch-file targets.txt -l 1"
