#!/bin/bash
#
# Pre-commit checks for security-compliance-cli
# Run this before making commits to catch issues early
#

set -e

echo "🔍 Running pre-commit checks..."

echo "📝 Checking code formatting..."
if ! cargo fmt --all -- --check; then
    echo "❌ Code formatting issues found. Run 'cargo fmt --all' to fix."
    exit 1
fi
echo "✅ Code formatting OK"

echo "🔧 Checking for linting issues..."
if ! cargo clippy --all-targets --all-features -- -D warnings; then
    echo "❌ Clippy linting issues found. Fix the warnings above."
    exit 1
fi
echo "✅ Linting OK"

echo "🧪 Running tests..."
if ! cargo test; then
    echo "❌ Tests failed. Fix the failing tests above."
    exit 1
fi
echo "✅ Tests OK"

echo "🏗️  Checking build..."
if ! cargo build --release; then
    echo "❌ Release build failed."
    exit 1
fi
echo "✅ Build OK"

echo "🎉 All pre-commit checks passed!"
