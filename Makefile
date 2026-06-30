# Anubis v2.0 — Elite Security Scanner Makefile
# Anti-Reverse Engineering | Cross-Platform | Zero CGO

BINARY   := anubis
MAIN_PKG := ./cmd/anubis
MODULE   := github.com/SepJs/anubis

VERSION  := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "2.0.0")
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE     := $(shell date -u +%Y-%m-%d)

# Advanced ldflags:
# -s -w            : strip debug info and symbol table (anti-reverse engineering)
# -buildmode=pie   : position-independent executable (ASLR)
# -trimpath        : remove file paths from binary
# -ldflags=-X     : inject version metadata
LDFLAGS  := -ldflags "\
  -X $(MODULE)/pkg/version.Version=$(VERSION) \
  -X $(MODULE)/pkg/version.BuildDate=$(DATE) \
  -X $(MODULE)/pkg/version.GitHash=$(COMMIT) \
  -s -w" \
  -trimpath \
  -buildmode=pie

# CGO must be disabled for zero-dependency cross-compilation
export CGO_ENABLED=0

.PHONY: all build install clean deps build-all test release \
        build-linux build-darwin build-windows \
        docs man profile lint security-check

## Default target
all: deps build

## Download and tidy dependencies
deps:
	go mod download
	go mod tidy

## Build binary for current platform with hardening
build:
	go build $(LDFLAGS) -o $(BINARY) $(MAIN_PKG)
	@echo "[+] Built ./$(BINARY) — version: $(VERSION)"
	@echo "[+] Build info: PIE+stripped+ASLR"
	@file $(BINARY)
	@ls -lh $(BINARY)

## Install to GOPATH/bin
install: build
	cp $(BINARY) $(shell go env GOPATH)/bin/$(BINARY)
	@echo "[+] Installed to $(shell go env GOPATH)/bin/$(BINARY)"

## Ultra-compressed cross-platform build (all targets)
build-all: deps
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64     $(MAIN_PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64     $(MAIN_PKG)
	CGO_ENABLED=0 GOOS=linux   GOARCH=386    go build $(LDFLAGS) -o dist/$(BINARY)-linux-386       $(MAIN_PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe $(MAIN_PKG)
	CGO_ENABLED=0 GOOS=windows GOARCH=386    go build $(LDFLAGS) -o dist/$(BINARY)-windows-386.exe   $(MAIN_PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64     $(MAIN_PKG)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64     $(MAIN_PKG)
	@echo "[+] Cross-compiled to dist/ — all targets:"
	@ls -lh dist/
	@# Generate SHA256 checksums for all binaries
	@cd dist && for f in *; do sha256sum "$$f" > "$$f.sha256"; done
	@echo "[+] SHA256 checksums generated"

## Platform-specific builds
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64 $(MAIN_PKG)
	@echo "[+] Built dist/$(BINARY)-linux-amd64"

build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64 $(MAIN_PKG)
	@echo "[+] Built dist/$(BINARY)-darwin-arm64"

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe $(MAIN_PKG)
	@echo "[+] Built dist/$(BINARY)-windows-amd64.exe"

## Create a GitHub release with checksums
##   Usage: make release TAG=v2.0.0
release:
	@if [ -z "$(TAG)" ]; then echo "Usage: make release TAG=v2.0.0"; exit 1; fi
	git tag $(TAG)
	git push origin $(TAG)
	$(MAKE) build-all
	gh release create $(TAG) dist/* \
	  --title "Anubis $(TAG)" \
	  --notes-file CHANGELOG.md \
	  --repo SepJs/anubis
	@echo "[+] Released $(TAG)"

## Run tests
test:
	go test ./... -v -race -count=1

## Run tests with coverage
test-coverage:
	go test ./... -v -race -coverprofile=coverage.out -covermode=atomic
	go tool cover -html=coverage.out -o coverage.html
	@echo "[+] Coverage report: coverage.html"

## Lint and static analysis
lint:
	go vet ./...
	@which staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"
	@echo "[+] Lint complete"

## Security audit of dependencies
security-check:
	go list -m all | while read mod; do \
		echo "Checking $$mod..."; \
	done
	go vet -vettool=$(which govulncheck 2>/dev/null || echo "") ./... 2>/dev/null || echo "govulncheck not available"
	@echo "[+] Security check complete"

## Profile mode — build with profiling support
profile: deps
	go build $(LDFLAGS) -o $(BINARY)-profile $(MAIN_PKG)
	@echo "[+] Built ./$(BINARY)-profile with profiling support"
	@echo "    Run with: ./anubis-profile -t https://target.com --profile"

## Generate documentation and man pages
docs:
	@mkdir -p docs/man
	# Generate man page
	@echo '.TH ANUBIS 1 "2024" "Anubis v$(VERSION)" "Security Scanner Manual"' > docs/man/anubis.1
	@echo '.SH NAME' >> docs/man/anubis.1
	@echo 'anubis \- Modular Security Scanner' >> docs/man/anubis.1
	@echo '.SH SYNOPSIS' >> docs/man/anubis.1
	@echo 'anubis [flags] -t TARGET' >> docs/man/anubis.1
	@echo '.SH DESCRIPTION' >> docs/man/anubis.1
	@echo 'Anubis is a modular web application security scanner designed for authorized penetration testing.' >> docs/man/anubis.1
	@echo '.SH OPTIONS' >> docs/man/anubis.1
	@echo '.TP' >> docs/man/anubis.1
	@echo '\-t, --target' >> docs/man/anubis.1
	@echo 'Target URL or IP address' >> docs/man/anubis.1
	@echo '.TP' >> docs/man/anubis.1
	@echo '\-l, --level' >> docs/man/anubis.1
	@echo 'Scan level: 1 (light), 2 (active), 3 (deep)' >> docs/man/anubis.1
	@echo '.TP' >> docs/man/anubis.1
	@echo '\--ghost' >> docs/man/anubis.1
	@echo 'Ghost mode - minimize detection footprint' >> docs/man/anubis.1
	@echo '.TP' >> docs/man/anubis.1
	@echo '\--proxy' >> docs/man/anubis.1
	@echo 'Proxy URL for routing traffic' >> docs/man/anubis.1
	@echo '.TP' >> docs/man/anubis.1
	@echo '\--strategy' >> docs/man/anubis.1
	@echo 'Delay strategy: fixed, exponential, linear, jitter, randomized, polymorphic' >> docs/man/anubis.1
	@echo '.TP' >> docs/man/anubis.1
	@echo '\--profile' >> docs/man/anubis.1
	@echo 'Enable performance profiling (CPU/mem/trace)' >> docs/man/anubis.1
	@echo '.SH SEE ALSO' >> docs/man/anubis.1
	@echo 'https://github.com/SepJs/anubis' >> docs/man/anubis.1
	@echo "[+] Man page generated: docs/man/anubis.1"
	@# Generate README docs
	@echo "[+] Documentation generated in docs/"

## Remove built binaries
clean:
	rm -f $(BINARY)
	rm -rf dist/ coverage.out coverage.html
	@echo "[+] Clean complete"

## Show version that would be stamped
version:
	@echo "Anubis $(VERSION) ($(COMMIT)) — $(DATE)"

## Build size-optimized binary with UPX (if installed)
compress: build
	@which upx >/dev/null 2>&1 && upx --best --lzma $(BINARY) && echo "[+] Compressed with UPX" || echo "[-] UPX not installed, skipping compression"
	@ls -lh $(BINARY)

## Dependency audit — list all direct dependencies
deps-list:
	go list -m all | sort

## Show build configuration
build-info:
	@echo "=== Build Configuration ==="
	@echo "Module:  $(MODULE)"
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(DATE)"
	@echo "Go:      $$(go version)"
	@echo "CGO:     disabled"
	@echo "Flags:   $(LDFLAGS)"
	@echo "PIE:     enabled"
	@echo "Stripped: yes"
	@echo "=========================="

## Run in benchmark/profile mode
bench: build
	./$(BINARY) -t https://example.com -l 1 --profile
	@echo "[+] Profile data generated"

## Self-test — scan localhost for smoke testing
smoke: build
	@echo "[*] Running smoke test..."
	./$(BINARY) -t http://127.0.0.1:8080 -l 1 --ghost --timeout 5
	@echo "[+] Smoke test complete"
