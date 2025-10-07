# Test Data Setup

## SSH Key Setup for Board Access

Copy and paste the following commands into your serial terminal to set up SSH access with the test Ed25519 key:

```bash
# Create .ssh directory with correct permissions
mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Create authorized_keys file and add the test public key
cat > ~/.ssh/authorized_keys << 'EOF'
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBhWHq3tk7Z0ITfA9Jwuvbnf/LU8zjRqEh4Ugw9Oqo+ test-keypair-for-security-compliance-cli
EOF

# Set correct permissions for authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Verify setup
ls -la ~/.ssh/
echo "SSH key setup complete"
```

## Test SSH Connection

After running the above commands on the board, test the connection from your host machine:

```bash
# Test SSH connection using the private key (direct path)
ssh -i test-data/test_ed25519 root@<BOARD_IP_ADDRESS>

# Or if you've run the install script, use the installed key
ssh -i ~/.ssh/test_ed25519 root@<BOARD_IP_ADDRESS>

# Or use the pre-configured host alias (if board IP is 192.168.0.36)
ssh test-board
```

## Running Security Compliance Tests

Once SSH key authentication is working, you can run the security compliance CLI without passwords:

```bash
# Run tests using automatic SSH key detection (recommended)
cargo run -- --host <BOARD_IP_ADDRESS> --user fio test

# Run tests with explicit SSH key path
cargo run -- --host <BOARD_IP_ADDRESS> --user fio --identity-file ~/.ssh/test_ed25519 test

# Run specific test suite
cargo run -- --host <BOARD_IP_ADDRESS> --user fio test --test-suite boot

# With the pre-configured host alias (if board IP is 192.168.0.36)
cargo run -- --host 192.168.0.36 --user fio test
```

**Note**: The CLI automatically tries SSH key authentication first using these locations in order:
1. Specified key path (if `--identity-file` is provided)
2. `~/.ssh/test_ed25519` (our test key)
3. `~/.ssh/id_ed25519`
4. `~/.ssh/id_rsa`
5. `~/.ssh/id_ecdsa`

If SSH key authentication fails, it falls back to password authentication.

## Key Information

- **Key Type**: Ed25519 (256-bit)
- **Private Key**: `test-data/test_ed25519`
- **Public Key**: `test-data/test_ed25519.pub`
- **Fingerprint**: `SHA256:C7qFc+kHm8Bg/IDpoT5f1R5d95aSWEzNBn6os8fRbjo`
- **Comment**: `test-keypair-for-security-compliance-cli`

## Security Note

⚠️ **This is a test keypair for development/testing purposes only. Do not use in production environments.**
