# Development Workflow

This document outlines the recommended development workflow for the Security Compliance CLI to ensure code quality and prevent CI failures.

## First Time Setup

**Set up the development environment with git hooks:**

```bash
# Install git pre-commit hooks and set up development tools
make setup
```

This will:
- Install a pre-commit hook that automatically runs quality checks
- Set up the development environment
- Test that everything works correctly

## Pre-Commit Checks

The git hook will automatically run before each commit, but you can also run checks manually:

```bash
# Option 1: Use the Makefile (recommended)
make check

# Option 2: Use the script directly
./scripts/pre-commit-check.sh

# Option 3: Run individual checks manually
cargo fmt --all -- --check    # Check formatting
cargo clippy --all-targets --all-features -- -D warnings  # Check linting
cargo test                     # Run tests
cargo build --release         # Check release build
```

## Recommended Workflow

1. **First time setup**: `make setup` (installs git hooks)
2. **Make your changes**
3. **Format code**: `make fmt` or `cargo fmt --all`
4. **Run pre-commit checks**: `make check` (optional, git hook will run automatically)
5. **Commit**: `git add . && git commit -m "your message"`
   - The pre-commit hook will automatically run and prevent bad commits
6. **Push**: `git push`

## Git Hook Behavior

The pre-commit hook will:
- ✅ **Automatically run** before each commit
- ❌ **Block commits** if any checks fail
- 🎨 **Check formatting** with `cargo fmt`
- 🔍 **Run linting** with `cargo clippy`
- 🧪 **Run tests** with `cargo test`
- 🏗️ **Verify build** with `cargo check`

### Bypassing the Hook

If you need to commit without running checks (not recommended):

```bash
git commit --no-verify -m "your message"
```

## Quick Commands

```bash
# Format and check everything
make fmt && make check

# One-liner for commit workflow
make check && git add . && git commit -m "your message" && git push
```

## CI Pipeline

The CI pipeline runs the same checks:
- Code formatting (`cargo fmt --check`)
- Linting (`cargo clippy`)
- Tests (`cargo test`)
- Build verification
- Security audit
- Multi-platform builds (Linux, macOS, Windows)

## Troubleshooting

### Formatting Issues
```bash
# Fix formatting issues
cargo fmt --all

# Check if formatting is correct
cargo fmt --all -- --check
```

### Linting Issues
```bash
# See detailed linting suggestions
cargo clippy --all-targets --all-features

# Fix automatically fixable issues
cargo clippy --fix --all-targets --all-features
```

### Test Failures
```bash
# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

## Git Hooks (Optional)

To automatically run checks before commits, you can set up a git pre-commit hook:

```bash
# Create the hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
exec ./scripts/pre-commit-check.sh
EOF

# Make it executable
chmod +x .git/hooks/pre-commit
```

This will automatically run all checks before each commit and prevent commits if checks fail.
