GO ?= go
GOLANGCI_LINT ?= golangci-lint
GORELEASER ?= goreleaser
BINARY ?= transom
MAIN ?= ./cmd/transom
BUILD_DIR ?= build
# pkgbuild wants a plain x.y.z, so pass VERSION without the leading v.
VERSION ?= 0.0.0
PKG_ID ?= com.github.leebaird.transom
PKG_ROOT ?= $(BUILD_DIR)/pkgroot
PKG_DIR ?= $(BUILD_DIR)/pkg
# go test fuzzes one target per run; each gets this long.
FUZZTIME ?= 10s
GOVULNCHECK_VERSION ?= v1.8.0

.PHONY: all build build-x86_64 build-arm64 build-darwin-arm64 clean debug-amd64 debug-arm64 darwin-debug-arm64 clean-debug fix fmt-check fuzz lint pie-check pkg-darwin-arm64 release-check snapshot test vet vulncheck tidy-check

all: build

build: build-x86_64 build-arm64 build-darwin-arm64

build-x86_64:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildmode=pie -ldflags "-s -w" -o $(BUILD_DIR)/$(BINARY)_x86_64 $(MAIN)

build-arm64:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildmode=pie -ldflags "-s -w" -o $(BUILD_DIR)/$(BINARY)_arm64 $(MAIN)

build-darwin-arm64:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -buildmode=pie -ldflags "-s -w" -o $(BUILD_DIR)/$(BINARY)_darwin_arm64 $(MAIN)

clean:
	rm -f $(BUILD_DIR)/$(BINARY)_x86_64 $(BUILD_DIR)/$(BINARY)_arm64 $(BUILD_DIR)/$(BINARY)_darwin_arm64
	rm -f $(BUILD_DIR)/$(BINARY)-debug-amd64 $(BUILD_DIR)/$(BINARY)-debug-arm64 $(BUILD_DIR)/$(BINARY)-darwin-debug-arm64
	rm -rf $(PKG_ROOT) $(PKG_DIR)
	rmdir $(BUILD_DIR) 2>/dev/null || true

debug-amd64:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -gcflags "all=-N -l" -o $(BUILD_DIR)/$(BINARY)-debug-amd64 $(MAIN)

debug-arm64:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -gcflags "all=-N -l" -o $(BUILD_DIR)/$(BINARY)-debug-arm64 $(MAIN)

darwin-debug-arm64:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -gcflags "all=-N -l" -o $(BUILD_DIR)/$(BINARY)-darwin-debug-arm64 $(MAIN)

clean-debug:
	rm -f $(BUILD_DIR)/$(BINARY)-debug-amd64 $(BUILD_DIR)/$(BINARY)-debug-arm64 $(BUILD_DIR)/$(BINARY)-darwin-debug-arm64

fix:
	$(GO) fix ./...

fmt-check:
	$(GOLANGCI_LINT) fmt --diff

fuzz:
	$(GO) test -run='^$$' -fuzz='^FuzzParse$$' -fuzztime=$(FUZZTIME) ./internal/target
	$(GO) test -run='^$$' -fuzz='^FuzzParsePortList$$' -fuzztime=$(FUZZTIME) ./internal/discover
	$(GO) test -run='^$$' -fuzz='^FuzzParseFile$$' -fuzztime=$(FUZZTIME) ./internal/check
	$(GO) test -run='^$$' -fuzz='^FuzzOutdatedBanner$$' -fuzztime=$(FUZZTIME) ./internal/check
	$(GO) test -run='^$$' -fuzz='^FuzzBannerHeaders$$' -fuzztime=$(FUZZTIME) ./internal/check
	$(GO) test -run='^$$' -fuzz='^FuzzDisallowPaths$$' -fuzztime=$(FUZZTIME) ./internal/check
	$(GO) test -run='^$$' -fuzz='^FuzzHTMLLinks$$' -fuzztime=$(FUZZTIME) ./internal/report

lint:
	$(GOLANGCI_LINT) run ./...

# Fails unless every binary GoReleaser left in dist/ is position independent.
# Run it after make snapshot.
pie-check:
	@set -e; found=0; for f in dist/*/$(BINARY); do \
		[ -f "$$f" ] || continue; found=1; \
		if file -b "$$f" | grep -Eq 'pie executable|PIE'; then echo "PIE      $$f"; \
		else echo "not PIE  $$f"; exit 1; fi; \
	done; \
	[ "$$found" = 1 ] || { echo "no binaries in dist/; run make snapshot first"; exit 1; }

# macOS only: pkgbuild ships with Xcode's command line tools. The package is unsigned.
pkg-darwin-arm64: build-darwin-arm64
	rm -rf $(PKG_ROOT)
	mkdir -p $(PKG_ROOT)/usr/local/bin $(PKG_DIR)
	install -m 0755 $(BUILD_DIR)/$(BINARY)_darwin_arm64 $(PKG_ROOT)/usr/local/bin/$(BINARY)
	pkgbuild --root $(PKG_ROOT) --identifier $(PKG_ID) --version $(VERSION) --ownership recommended --install-location / $(PKG_DIR)/$(BINARY)_$(VERSION)_darwin_arm64.pkg

release-check:
	$(GORELEASER) check

snapshot:
	$(GORELEASER) release --snapshot --clean

test:
	$(GO) test -race -mod=readonly ./...
	$(GO) test -mod=readonly ./...

vet:
	$(GO) vet -mod=readonly ./...

vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

tidy-check:
	$(GO) mod tidy -go=1.27 -diff
