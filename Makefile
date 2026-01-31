.PHONY: all build test test-unit test-e2e test-full clean machine-start machine-stop machine-status help

# Default target
all: build

# Build the devkit binary
build:
	go build -o devkit ./cmd/devkit

# Run unit tests only (no Podman required)
test-unit:
	go test ./internal/... -v -count=1

# Run e2e tests (requires running Podman machine)
test-e2e: ensure-machine
	go test ./tests/e2e/... -v -count=1

# Run all tests
test: test-unit test-e2e

# Run full test suite including long-running tests
test-full: ensure-machine
	go test ./... -v -count=1

# Quick test (skip tests requiring Podman)
test-quick:
	go test ./... -short -count=1

# Ensure a Podman machine is running
ensure-machine:
	@echo "Checking Podman machine status..."
	@if ! podman info >/dev/null 2>&1; then \
		echo "No Podman machine running. Starting one..."; \
		$(MAKE) machine-start; \
	else \
		echo "Podman machine is running."; \
	fi

# Start a Podman machine (prefers devkit machine if it exists)
machine-start:
	@echo "Starting Podman machine..."
	@if podman machine list --format '{{.Name}}' | grep -q '^devkit$$'; then \
		echo "Starting devkit machine..."; \
		podman machine start devkit || true; \
		podman system connection default devkit; \
	elif podman machine list --format '{{.Name}}' | grep -q '^podman-machine-default$$'; then \
		echo "Starting default machine..."; \
		podman machine start podman-machine-default || true; \
		podman system connection default podman-machine-default; \
	else \
		echo "No machine found. Creating devkit machine..."; \
		podman machine init devkit --cpus 2 --memory 4096 --disk-size 20; \
		podman machine start devkit; \
		podman system connection default devkit; \
	fi
	@echo "Waiting for machine to be ready..."
	@sleep 5
	@podman info >/dev/null 2>&1 && echo "Machine is ready!" || echo "Machine may still be starting..."

# Stop all Podman machines
machine-stop:
	@echo "Stopping all Podman machines..."
	@podman machine list --format '{{.Name}}' | xargs -I {} podman machine stop {} 2>/dev/null || true
	@echo "All machines stopped."

# Show machine status
machine-status:
	@podman machine list

# Run security attack tests
test-security: ensure-machine
	go test ./tests/e2e -v -run "TestAttack|TestSecurity" -count=1

# Run CDP filter attack tests (no Podman required)
test-filter:
	go test ./internal/debugproxy -v -run "TestAttack" -count=1

# Clean build artifacts
clean:
	rm -f devkit
	go clean -testcache

# Install dependencies
deps:
	go mod tidy
	go mod download

# Build and install
install: build
	cp devkit /usr/local/bin/devkit

# Show help
help:
	@echo "Devkit Makefile targets:"
	@echo ""
	@echo "  build          - Build the devkit binary"
	@echo "  test           - Run all tests (starts machine if needed)"
	@echo "  test-unit      - Run unit tests only (no Podman required)"
	@echo "  test-e2e       - Run e2e tests (requires Podman)"
	@echo "  test-quick     - Quick test run (skips Podman tests)"
	@echo "  test-full      - Run full test suite"
	@echo "  test-security  - Run security/attack tests"
	@echo "  test-filter    - Run CDP filter tests (no Podman)"
	@echo ""
	@echo "  machine-start  - Start a Podman machine"
	@echo "  machine-stop   - Stop all Podman machines"
	@echo "  machine-status - Show Podman machine status"
	@echo ""
	@echo "  clean          - Clean build artifacts"
	@echo "  deps           - Install/update dependencies"
	@echo "  install        - Install devkit to /usr/local/bin"
	@echo "  help           - Show this help"
