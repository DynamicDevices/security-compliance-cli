#!/bin/bash

# Install Test SSH Key Script
# This script installs the test Ed25519 key to the local system for easy SSH access

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEST_KEY_DIR="${PROJECT_ROOT}/test-data"
TEST_PRIVATE_KEY="${TEST_KEY_DIR}/test_ed25519"
TEST_PUBLIC_KEY="${TEST_KEY_DIR}/test_ed25519.pub"

# SSH directory
SSH_DIR="${HOME}/.ssh"
SSH_CONFIG="${SSH_DIR}/config"

echo -e "${BLUE}Security Compliance CLI - Test Key Installation${NC}"
echo "=================================================="

# Check if test keys exist
if [[ ! -f "${TEST_PRIVATE_KEY}" ]] || [[ ! -f "${TEST_PUBLIC_KEY}" ]]; then
    echo -e "${RED}Error: Test keys not found in ${TEST_KEY_DIR}${NC}"
    echo "Please run the key generation first or check the test-data directory."
    exit 1
fi

# Create SSH directory if it doesn't exist
if [[ ! -d "${SSH_DIR}" ]]; then
    echo -e "${YELLOW}Creating SSH directory: ${SSH_DIR}${NC}"
    mkdir -p "${SSH_DIR}"
    chmod 700 "${SSH_DIR}"
fi

# Copy the test keys to SSH directory
echo -e "${BLUE}Installing test keys to ${SSH_DIR}${NC}"
cp "${TEST_PRIVATE_KEY}" "${SSH_DIR}/test_ed25519"
cp "${TEST_PUBLIC_KEY}" "${SSH_DIR}/test_ed25519.pub"

# Set correct permissions
chmod 600 "${SSH_DIR}/test_ed25519"
chmod 644 "${SSH_DIR}/test_ed25519.pub"

echo -e "${GREEN}✓ Test keys installed successfully${NC}"

# Add SSH config entry for easy access
echo -e "${BLUE}Adding SSH config entry${NC}"

# Check if config file exists
if [[ ! -f "${SSH_CONFIG}" ]]; then
    touch "${SSH_CONFIG}"
    chmod 600 "${SSH_CONFIG}"
fi

# Check if test host entry already exists
if ! grep -q "Host test-board" "${SSH_CONFIG}"; then
    cat >> "${SSH_CONFIG}" << EOF

# Security Compliance CLI Test Board
Host test-board
    HostName 192.168.0.36
    User root
    IdentityFile ~/.ssh/test_ed25519
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

# Generic test host template (update IP as needed)
Host test-host
    HostName <UPDATE_IP_ADDRESS>
    User root
    IdentityFile ~/.ssh/test_ed25519
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
    echo -e "${GREEN}✓ SSH config entries added${NC}"
else
    echo -e "${YELLOW}SSH config entry already exists${NC}"
fi

# Display key information
echo ""
echo -e "${BLUE}Test Key Information:${NC}"
echo "===================="
ssh-keygen -l -f "${SSH_DIR}/test_ed25519.pub"

echo ""
echo -e "${BLUE}Usage Examples:${NC}"
echo "==============="
echo -e "${GREEN}# Connect to test board (if IP is 192.168.0.36):${NC}"
echo "ssh test-board"
echo ""
echo -e "${GREEN}# Connect to custom IP:${NC}"
echo "ssh -i ~/.ssh/test_ed25519 root@<IP_ADDRESS>"
echo ""
echo -e "${GREEN}# Run security compliance tests:${NC}"
echo "cargo run -- test --host 192.168.0.36"
echo ""
echo -e "${YELLOW}Note: Update the IP address in ~/.ssh/config for your specific board${NC}"

echo ""
echo -e "${GREEN}Installation complete!${NC}"
