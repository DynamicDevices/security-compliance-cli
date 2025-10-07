#!/bin/bash
#
# Setup script for development environment
# Installs git hooks and sets up development tools
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 Setting up development environment for security-compliance-cli...${NC}"

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo -e "${RED}❌ Not in a Git repository. Please run this from the project root.${NC}"
    exit 1
fi

# Check if we're in the right project
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}❌ Not in a Rust project directory${NC}"
    exit 1
fi

# Install pre-commit hook
echo -e "${YELLOW}📝 Installing git pre-commit hook...${NC}"
if [ -f ".git/hooks/pre-commit" ]; then
    echo -e "${YELLOW}⚠️  Pre-commit hook already exists. Backing up...${NC}"
    mv .git/hooks/pre-commit .git/hooks/pre-commit.backup
fi

cp scripts/git-hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo -e "${GREEN}✅ Pre-commit hook installed${NC}"

# Test the hook
echo -e "${YELLOW}🧪 Testing pre-commit hook...${NC}"
if .git/hooks/pre-commit; then
    echo -e "${GREEN}✅ Pre-commit hook test passed${NC}"
else
    echo -e "${RED}❌ Pre-commit hook test failed${NC}"
    echo -e "${YELLOW}💡 You may need to fix code issues before the hook will work${NC}"
fi

# Install additional git hooks if they exist
for hook in scripts/git-hooks/*; do
    if [ -f "$hook" ] && [ "$(basename "$hook")" != "pre-commit" ]; then
        hook_name=$(basename "$hook")
        echo -e "${YELLOW}📝 Installing $hook_name hook...${NC}"
        cp "$hook" ".git/hooks/$hook_name"
        chmod +x ".git/hooks/$hook_name"
        echo -e "${GREEN}✅ $hook_name hook installed${NC}"
    fi
done

echo -e "${GREEN}🎉 Development environment setup complete!${NC}"
echo ""
echo -e "${BLUE}📋 What's been set up:${NC}"
echo -e "  • Pre-commit hook that runs formatting, linting, and tests"
echo -e "  • Automatic code quality checks before each commit"
echo ""
echo -e "${BLUE}📖 Usage:${NC}"
echo -e "  • Use 'make check' to run checks manually"
echo -e "  • Use 'make fmt' to format code"
echo -e "  • Git commits will now automatically run quality checks"
echo -e "  • See docs/DEVELOPMENT.md for detailed workflow"
echo ""
echo -e "${YELLOW}💡 To disable the hook temporarily:${NC}"
echo -e "  git commit --no-verify"
