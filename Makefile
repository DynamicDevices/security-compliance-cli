# Security Compliance CLI - Development Makefile
.PHONY: check fmt lint test build clean pre-commit setup help

# Default target
help:
	@echo "Security Compliance CLI Development Commands:"
	@echo ""
	@echo "  make setup      - Set up development environment (install git hooks)"
	@echo "  make check      - Run all pre-commit checks"
	@echo "  make fmt        - Format code with rustfmt"
	@echo "  make lint       - Run clippy linter"
	@echo "  make test       - Run all tests"
	@echo "  make build      - Build release version"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make pre-commit - Run pre-commit checks (alias for check)"
	@echo ""
	@echo "Quick setup:"
	@echo "  make setup      - First time setup (installs git hooks)"
	@echo ""
	@echo "Quick workflow:"
	@echo "  make check && git add . && git commit -m 'your message'"

# Set up development environment
setup:
	@echo "🔧 Setting up development environment..."
	@./scripts/setup-dev.sh

# Run all pre-commit checks
check:
	@echo "🔍 Running pre-commit checks..."
	@./scripts/pre-commit-check.sh

# Alias for check
pre-commit: check

# Format code
fmt:
	@echo "📝 Formatting code..."
	@cargo fmt --all

# Run linter
lint:
	@echo "🔧 Running linter..."
	@cargo clippy --all-targets --all-features -- -D warnings

# Run tests
test:
	@echo "🧪 Running tests..."
	@cargo test

# Build release
build:
	@echo "🏗️  Building release..."
	@cargo build --release

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@cargo clean
