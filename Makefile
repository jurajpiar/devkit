.PHONY: all build proxy test test-e2e install clean

GUEST_ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
PROXY_BIN := internal/embedded/bin/egressproxy-linux-$(GUEST_ARCH)

all: build

# Cross-compile the egress proxy for the Linux guest, then embed it in devkit.
build: proxy
	go build -o devkit ./cmd/devkit

proxy:
	GOOS=linux GOARCH=$(GUEST_ARCH) CGO_ENABLED=0 \
		go build -trimpath -ldflags="-s -w" -o $(PROXY_BIN) ./cmd/egressproxy

# Unit tests. No VM required.
test:
	go test ./internal/... -count=1

# End-to-end: creates a real VM (several minutes on first run). Requires Lima.
test-e2e: build
	DEVKIT_E2E=1 go test ./tests/e2e/... -v -count=1 -timeout 30m

install: build
	install -m 755 devkit /usr/local/bin/devkit

clean:
	rm -f devkit $(PROXY_BIN)
	go clean -testcache
