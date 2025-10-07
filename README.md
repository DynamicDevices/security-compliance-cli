# Security Compliance CLI

A comprehensive security compliance testing tool for Dynamic Devices embedded systems, specifically designed for i.MX93-based devices running Foundries.io Linux Micro Platform.

## Features

🔒 **Comprehensive Security Testing**
- Boot security (Secure Boot, AHAB, signature verification)
- Runtime security (filesystem encryption, firewall, SELinux)
- Hardware security (EdgeLock Enclave, crypto acceleration)
- Network security (port scanning, service hardening)
- Compliance verification (EU CRA, UK CE RED)

🎯 **Automated Compliance Checking**
- EU Cyber Resilience Act (CRA) Article 11 data protection
- UK CE Radio Equipment Directive (RED) Essential Requirements 3.3
- Automated vulnerability management verification
- Incident response capability assessment

📊 **Multiple Output Formats**
- Human-readable with colors and progress bars
- JSON for programmatic processing
- JUnit XML for CI/CD integration
- Markdown reports for documentation

🚀 **Easy Integration**
- SSH-based remote testing
- Configurable test suites
- Parallel test execution support
- Detailed logging and audit trails

## Quick Start

### Installation

```bash
# Clone the repository
git clone git@github.com:DynamicDevices/security-compliance-cli.git
cd security-compliance-cli

# Build the application
cargo build --release

# Install (optional)
cargo install --path .
```

### Basic Usage

```bash
# Run all security compliance tests
security-compliance-cli test --host 192.168.0.36 --user fio --password fio

# Run specific test suite
security-compliance-cli test --test-suite boot --host 192.168.0.36

# Generate JSON report
security-compliance-cli test --format json --output results.json

# List available tests
security-compliance-cli list
```

## Test Suites

### 🥾 Boot Security Tests
- **boot_001**: Secure Boot Enabled (AHAB verification)
- **boot_002**: U-Boot Signature Verification
- **boot_003**: Kernel Signature Verification
- **boot_004**: Module Signing Active
- **boot_005**: OP-TEE Signature Verification
- **boot_006**: TF-A Signature Verification
- **boot_007**: Complete Boot Chain Verification

### ⚙️ Runtime Security Tests
- **runtime_001**: Filesystem Encryption (LUKS)
- **runtime_002**: Firewall Configuration
- **runtime_003**: SELinux Status
- **runtime_004**: SSH Security Configuration
- **runtime_005**: User Permission Security
- **runtime_006**: Service Hardening
- **runtime_007**: Kernel Security Protections

### 🔧 Hardware Security Tests
- **hardware_001**: EdgeLock Enclave (ELE)
- **hardware_002**: Secure Enclave Status
- **hardware_003**: Hardware Root of Trust
- **hardware_004**: Crypto Hardware Acceleration
- **hardware_005**: Hardware RNG

### 🌐 Network Security Tests
- **network_001**: Open Network Ports
- **network_002**: Network Services Security
- **network_003**: WiFi Security Configuration
- **network_004**: Bluetooth Security
- **network_005**: Network Encryption

### 📋 Compliance Tests
- **compliance_001**: CRA Data Protection (Article 11)
- **compliance_002**: CRA Vulnerability Management
- **compliance_003**: RED Security Requirements (3.3)
- **compliance_004**: Incident Response Capability
- **compliance_005**: Security Audit Logging

## Configuration

### Command Line Options

```bash
security-compliance-cli [OPTIONS] <COMMAND>

Options:
  -H, --host <HOST>           Target IP address [default: 192.168.0.36]
  -p, --port <PORT>           Target SSH port [default: 22]
  -u, --user <USER>           SSH username [default: fio]
  -P, --password <PASSWORD>   SSH password [default: fio]
      --timeout <TIMEOUT>     SSH connection timeout in seconds [default: 30]
  -f, --format <FORMAT>       Output format [default: human] [possible values: human, json, junit, markdown]
  -v, --verbose               Verbose output (can be used multiple times)
  -c, --config <CONFIG>       Configuration file
  -o, --output <OUTPUT>       Output file for results

Commands:
  test      Run security compliance tests
  list      List available tests
  validate  Validate configuration file
```

### Configuration File

Create a `config.toml` file for persistent settings:

```toml
[target]
host = "192.168.0.36"
port = 22
user = "fio"
password = "fio"
timeout = 30
ssh_multiplex = true

[output]
format = "human"
verbose = 1
colors = true

[tests]
suite = "all"
continue_on_failure = false
parallel = false
timeout_per_test = 60
retries = 1

[thresholds]
boot_time_max_ms = 30000
memory_usage_max_mb = 512
cpu_usage_max_percent = 80.0
```

## Example Output

### Human-Readable Format

```
🔒 Security Compliance Testing
================================
Suite: All
Tests: 27

✅ boot_001 - Secure Boot Enabled: AHAB secure boot detected
✅ boot_002 - U-Boot Signature Verification: FIT image verification active
❌ runtime_001 - Filesystem Encryption (LUKS): No filesystem encryption detected
⚠️  network_001 - Open Network Ports: Some security concerns (8 ports, 1 risky)

📊 Test Results Summary
======================

Overall Status: FAILED
Success Rate: 85.2%

📈 Statistics:
  Total Tests: 27
  ✅ Passed: 23
  ❌ Failed: 2
  ⚠️  Warnings: 2
  ⏭️  Skipped: 0
  💥 Errors: 0

⏱️  Duration: 45.2s

❌ Failed Tests:
  • runtime_001 - Filesystem Encryption (LUKS): No filesystem encryption detected
  • compliance_001 - CRA Data Protection (Article 11): CRA non-compliant (1/4 items)
```

### JSON Format

```json
{
  "suite_name": "All",
  "total_tests": 27,
  "passed": 23,
  "failed": 2,
  "warnings": 2,
  "skipped": 0,
  "errors": 0,
  "duration": {
    "secs": 45,
    "nanos": 200000000
  },
  "timestamp": "2025-10-07T10:30:00Z",
  "system_info": {
    "kernel_version": "6.1.70-lmp-standard",
    "uname": "Linux imx93-jaguar-eink 6.1.70-lmp-standard #1 SMP PREEMPT",
    "uptime": "up 2 days, 14:32",
    "memory_info": "MemTotal: 2097152 kB",
    "os_release": "VERSION_ID=\"4.0.20\""
  },
  "results": [
    {
      "test_id": "boot_001",
      "test_name": "Secure Boot Enabled",
      "category": "boot",
      "status": "Passed",
      "message": "AHAB secure boot detected",
      "details": "AHAB initialization successful",
      "duration": {
        "secs": 1,
        "nanos": 250000000
      },
      "timestamp": "2025-10-07T10:30:01Z",
      "metadata": {}
    }
  ]
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Compliance Check
on: [push, pull_request]

jobs:
  security-compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
      - name: Build security-compliance-cli
        run: cargo build --release
      - name: Run security tests
        run: |
          ./target/release/security-compliance-cli test \
            --host ${{ secrets.TARGET_HOST }} \
            --user ${{ secrets.TARGET_USER }} \
            --password ${{ secrets.TARGET_PASSWORD }} \
            --format junit \
            --output security-results.xml
      - name: Publish Test Results
        uses: EnricoMi/publish-unit-test-result-action@v2
        if: always()
        with:
          files: security-results.xml
```

## Development

### Building from Source

```bash
# Development build
cargo build

# Release build
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- test --host 192.168.0.36
```

### Adding New Tests

1. Create a new test in the appropriate module (`tests/boot.rs`, `tests/runtime.rs`, etc.)
2. Implement the `SecurityTest` trait
3. Register the test in `TestRegistry::new()`
4. Add documentation and examples

Example:

```rust
pub enum MyTests {
    CustomSecurityCheck,
}

#[async_trait]
impl SecurityTest for MyTests {
    async fn run(&self, target: &mut Target) -> Result<TestResult> {
        // Implementation here
    }
    
    fn test_id(&self) -> &str { "custom_001" }
    fn test_name(&self) -> &str { "Custom Security Check" }
    fn category(&self) -> &str { "custom" }
    fn description(&self) -> &str { "Description of the test" }
}
```

## Hardware Requirements

- **Target Platform**: i.MX93-based devices (imx93-jaguar-eink)
- **Operating System**: Foundries.io Linux Micro Platform v95+
- **Network**: SSH access (port 22) with credentials
- **Minimum System Requirements**: 512MB RAM, 1GB storage

## Security Features Tested

### Boot Security
- ✅ AHAB (Advanced High Assurance Boot)
- ✅ U-Boot signature verification
- ✅ Kernel image signing
- ✅ Kernel module signing
- ✅ OP-TEE trusted OS verification
- ✅ TF-A (ARM Trusted Firmware) signing

### Runtime Security
- ✅ LUKS filesystem encryption
- ✅ iptables firewall configuration
- ✅ SELinux mandatory access control
- ✅ SSH hardening
- ✅ User permission auditing
- ✅ System service security

### Hardware Security
- ✅ i.MX93 EdgeLock Enclave (ELE)
- ✅ Hardware root of trust
- ✅ Cryptographic acceleration (CAAM)
- ✅ Hardware random number generator
- ✅ Secure key storage

### Network Security
- ✅ Port scanning and service enumeration
- ✅ WiFi security (WPA3/WPA2)
- ✅ Bluetooth security configuration
- ✅ Network encryption capabilities
- ✅ Firewall rule validation

### Compliance Verification
- ✅ EU CRA Article 11 (Data Protection)
- ✅ EU CRA Vulnerability Management
- ✅ UK CE RED Essential Requirements 3.3
- ✅ Incident response capabilities
- ✅ Security audit logging

## Troubleshooting

### Common Issues

**SSH Connection Failed**:
```bash
# Check network connectivity
ping 192.168.0.36

# Test SSH manually
ssh fio@192.168.0.36

# Use verbose mode for debugging
security-compliance-cli test --verbose --host 192.168.0.36
```

**Permission Denied**:
```bash
# Ensure SSH key is properly configured
ssh-copy-id fio@192.168.0.36

# Or use password authentication
security-compliance-cli test --password your_password
```

**Test Timeouts**:
```bash
# Increase timeout
security-compliance-cli test --timeout 60

# Run specific test suite only
security-compliance-cli test --test-suite boot
```

## Support

- **Maintainer**: Alex J Lennon <ajlennon@dynamicdevices.co.uk>
- **Company**: Dynamic Devices Ltd
- **Issues**: [GitHub Issues](https://github.com/DynamicDevices/security-compliance-cli/issues)
- **Documentation**: [Project Wiki](https://github.com/DynamicDevices/security-compliance-cli/wiki)

## License

Copyright (c) 2025 Dynamic Devices Ltd. All rights reserved.

This software is proprietary and confidential. See LICENSE for full terms.

## Related Projects

- [eink-power-cli](https://github.com/DynamicDevices/eink-power-cli) - Power management CLI
- [meta-dynamicdevices](https://github.com/DynamicDevices/meta-dynamicdevices) - Yocto BSP layers
- [Foundries.io](https://foundries.io) - Linux Micro Platform
