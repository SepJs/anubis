# Anubis Security Scanner — Makefile
# GitHub: https://github.com/SepJs/anubis
# Author: Unknown XRG
#
# Version is read from the latest Git tag so the binary's --version output
# always matches the GitHub release tag automatically:
#   git tag v1.2.0 && git push origin v1.2.0 → binary shows "Anubis v1.2.0"

BINARY   := anubis
MAIN_PKG := ./cmd/anubis
MODULE   := github.com/SepJs/anubis

# Read version from git tag; fall back to "dev" on untagged repos
VERSION  := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev")
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE     := $(shell date -u +%Y-%m-%d)

LDFLAGS  := -ldflags "\
  -X $(MODULE)/pkg/version.Version=$(VERSION) \
  -X $(MODULE)/pkg/version.BuildDate=$(DATE) \
  -X $(MODULE)/pkg/version.GitHash=$(COMMIT) \
  -s -w"

.PHONY: all build install clean deps build-all test release

## Default target
all: deps build

## Download and tidy dependencies (also generates go.sum)
deps:
	go mod download
	go mod tidy

## Build binary for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) $(MAIN_PKG)
	@echo "[+] Built ./$(BINARY) — version: $(VERSION)"

## Install to GOPATH/bin
install: build
	cp $(BINARY) $(shell go env GOPATH)/bin/$(BINARY)
	@echo "[+] Installed to $(shell go env GOPATH)/bin/$(BINARY)"

## Cross-compile for all platforms
build-all: deps
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64   $(MAIN_PKG)
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64   $(MAIN_PKG)
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe $(MAIN_PKG)
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64  $(MAIN_PKG)
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64  $(MAIN_PKG)
	@echo "[+] Cross-compiled to dist/"

## Create a GitHub release (requires gh CLI and a tag to be pushed first)
##   Usage: make release TAG=v1.2.0
release:
	@if [ -z "$(TAG)" ]; then echo "Usage: make release TAG=v1.2.0"; exit 1; fi
	git tag $(TAG)
	git push origin $(TAG)
	$(MAKE) build-all
	gh release create $(TAG) dist/* \
	  --title "Anubis $(TAG)" \
	  --notes "Release $(TAG)" \
	  --repo SepJs/anubis
	@echo "[+] Released $(TAG)"

## Run tests
test:
	go test ./... -v

## Remove built binaries
clean:
	rm -f $(BINARY)
	rm -rf dist/

## Show version that would be stamped
version:
	@echo "$(VERSION) ($(COMMIT)) — $(DATE)"
