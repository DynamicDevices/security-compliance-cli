# SSH Key Installation Guide

The Security Compliance CLI provides a convenient way to install SSH public keys on target devices via serial console. This is essential for testing scenarios where password authentication is disabled.

## Overview

The `install-ssh-key` command allows you to:
- Generate temporary SSH key pairs with configurable validity periods
- Install existing SSH public keys from files
- Automatically configure the target device for SSH key authentication
- Test the SSH connection after key installation

## Quick Start

### Basic Usage (Generate Temporary Key)

```bash
# Generate a temporary key (valid for 1 hour) and install it
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key

# Generate a key valid for 8 hours
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key --key-validity-hours 8

# Save the generated private key for later use
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key \
    --save-private-key ./temp_ssh_key \
    --key-validity-hours 24
```

### Using Existing Public Key

```bash
# Install an existing public key
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key \
    --public-key-file ~/.ssh/id_rsa.pub
```

### Advanced Options

```bash
# Full configuration example
security-compliance-cli \
    --serial-device /dev/ttyUSB0 \
    --serial-username root \
    --serial-password mypassword \
    install-ssh-key \
    --target-user fio \
    --key-validity-hours 12 \
    --save-private-key ./my_test_key \
    --test-connection
```

## Command Options

### Connection Options (Global)
- `--serial-device`: Serial device path (e.g., `/dev/ttyUSB0`, `COM3`)
- `--serial-username`: Username for serial login
- `--serial-password`: Password for serial login
- `--baud-rate`: Serial baud rate (default: 115200)

### Key Management Options
- `--public-key-file`: Path to existing SSH public key file
- `--key-validity-hours`: Validity period for generated keys (default: 1 hour)
- `--save-private-key`: Path to save generated private key
- `--target-user`: Username to install the key for
- `--test-connection`: Test SSH connection after installation (default: true)

## Key Generation Details

### Temporary Keys
When no `--public-key-file` is specified, the tool generates a new Ed25519 SSH key pair:
- **Algorithm**: Ed25519 (modern, secure, fast)
- **Default Validity**: 1 hour
- **Comment**: Includes generation timestamp and expiration time
- **Format**: OpenSSH compatible

### Key Expiration
Generated keys include expiration information in the comment field:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... security-compliance-cli-temp-key-20250107-143022 expires:2025-01-07 15:30:22 UTC
```

**Note**: The expiration is informational only. The key remains valid on the target system until manually removed.

## Workflow

1. **Connect**: Establish serial console connection to target device
2. **Authenticate**: Log in using serial credentials
3. **Generate/Load Key**: Create new key pair or load existing public key
4. **Install Key**: Add public key to `~/.ssh/authorized_keys`
5. **Set Permissions**: Configure proper file permissions (600/700)
6. **Test Connection**: Optionally test SSH connection with new key

## File Operations

The tool performs these operations on the target device:
```bash
# Create .ssh directory
mkdir -p /home/USERNAME/.ssh

# Set directory permissions
chmod 700 /home/USERNAME/.ssh

# Add public key
echo "ssh-ed25519 ..." >> /home/USERNAME/.ssh/authorized_keys

# Set file permissions
chmod 600 /home/USERNAME/.ssh/authorized_keys

# Set ownership
chown -R USERNAME:USERNAME /home/USERNAME/.ssh
```

## Security Considerations

### Temporary Keys
- Default 1-hour validity provides good security/convenience balance
- Keys are not automatically removed from target (manual cleanup required)
- Private keys are stored in memory only (unless `--save-private-key` used)

### File Permissions
- Private key files saved with 600 permissions (owner read/write only)
- Target device SSH directory and files configured with proper permissions

### Connection Testing
- SSH connection test validates key installation
- Uses the same host/port configured for the tool
- Helps identify SSH server configuration issues

## Troubleshooting

### Serial Connection Issues
```bash
# Check device permissions
ls -l /dev/ttyUSB*
sudo chmod 666 /dev/ttyUSB0  # Temporary fix

# Verify device is not in use
lsof /dev/ttyUSB0
```

### SSH Connection Test Failures
- Verify SSH server is running on target: `systemctl status ssh`
- Check SSH server configuration: `/etc/ssh/sshd_config`
- Ensure `PubkeyAuthentication yes` is set
- Check SSH server logs: `journalctl -u ssh`

### Key Installation Issues
- Verify target user exists: `id USERNAME`
- Check home directory permissions
- Ensure sufficient disk space in home directory

## Examples

### Development Testing
```bash
# Quick temporary access for 2 hours
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key \
    --key-validity-hours 2 \
    --save-private-key ./dev_key

# Connect using the generated key
ssh -i ./dev_key fio@192.168.0.36
```

### CI/CD Integration
```bash
# Use existing key from CI system
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key \
    --public-key-file $CI_SSH_PUBLIC_KEY \
    --target-user root \
    --no-test-connection
```

### Long-term Testing
```bash
# 24-hour validity for extended testing
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key \
    --key-validity-hours 24 \
    --save-private-key ~/.ssh/test_device_key \
    --target-user fio
```

## Integration with Other Commands

After installing an SSH key, you can use other tool commands via SSH:

```bash
# Install key via serial
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key \
    --save-private-key ./device_key

# Run tests via SSH using the installed key
security-compliance-cli --identity-file ./device_key test

# Detect device type via SSH
security-compliance-cli --identity-file ./device_key detect
```

This workflow enables seamless transition from serial-based key installation to SSH-based testing and operations.
