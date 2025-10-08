# Security Compliance CLI

A comprehensive security compliance testing tool for embedded Linux systems, with specialized support for i.MX93 and i.MX8MM platforms running Foundries.io Linux Micro Platform. Features cross-platform SSH key management, serial console communication, and automated compliance reporting.

## Features

🔒 **Comprehensive Security Testing**
- Boot security (Secure Boot, AHAB, signature verification)
- Runtime security (filesystem encryption, firewall, SELinux)
- Hardware security (EdgeLock Enclave, CAAM, PCF2131 RTC)
- Network security (port scanning, service hardening)
- Compliance verification (EU CRA, UK CE RED)
- Container security (Docker/Podman, isolation, namespaces)
- Certificate management (PKI, X.509, TLS validation)
- Production hardening (debug disabled, monitoring, backups)
- Machine-specific testing (auto-detection of platform features)

🎓 **Educational Verbose Mode**
- Detailed test descriptions explaining security concepts
- Two verbosity levels: `-v` for test purposes, `-vv` for categories
- Helps users understand why each test is important
- Educational output for security learning

🎯 **Automated Compliance Checking**
- EU Cyber Resilience Act (CRA) Article 11 data protection
- UK CE Radio Equipment Directive (RED) Essential Requirements 3.3
- Automated vulnerability management verification
- Incident response capability assessment
- Testing modes: Pre-production and Production

📊 **Multiple Output Formats**
- Human-readable with colors and progress bars
- JSON for programmatic processing
- JUnit XML for CI/CD integration
- Markdown reports for documentation
- EU CRA compliance reports
- UK CE RED compliance reports
- PDF reports for formal documentation

🚀 **Easy Integration**
- SSH-based remote testing (Linux, macOS, Windows)
- Serial console communication (Linux, macOS, Windows)
- SSH key management (generate, install, verify, remove)
- Machine auto-detection (i.MX93 E-Ink, i.MX8MM Sentai)
- Configurable test suites with platform filtering
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

### Board Setup

The tool supports both SSH and serial console communication:

#### SSH Setup (Recommended)
```bash
# Install SSH key via serial console (All platforms)
# Linux/macOS
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key --key-validity-hours 2

# Windows
security-compliance-cli --serial-device COM3 install-ssh-key --key-validity-hours 2

# Or manually configure SSH access
ssh-copy-id fio@192.168.0.36
```

#### Serial Console Setup
```bash
# Direct serial communication (All platforms)
# Linux/macOS
security-compliance-cli --serial-device /dev/ttyUSB0 --serial-username fio test

# Windows
security-compliance-cli --serial-device COM3 --serial-username fio test
```

See [docs/SSH_KEY_INSTALLATION.md](docs/SSH_KEY_INSTALLATION.md) for detailed SSH key management and [docs/SERIAL_SETUP.md](docs/SERIAL_SETUP.md) for serial console configuration.

### Basic Usage

#### SSH Communication (All Platforms)
```bash
# Run tests with SSH key authentication (recommended)
security-compliance-cli --host 192.168.0.36 --user fio test

# Run with machine auto-detection
security-compliance-cli --host 192.168.0.36 --user fio test --verbose

# Run specific machine tests
security-compliance-cli --host 192.168.0.36 --user fio --machine imx93-jaguar-eink test

# Generate compliance reports
security-compliance-cli --host 192.168.0.36 test --format cra --output cra-report.md
security-compliance-cli --host 192.168.0.36 test --format red --output red-report.md
security-compliance-cli --host 192.168.0.36 test --format pdf --output report.pdf
```

#### Serial Console Communication (Linux/macOS)
```bash
# Direct serial testing
security-compliance-cli --serial-device /dev/ttyUSB0 --serial-username fio test

# Install SSH key via serial
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key --key-validity-hours 2

# Check installed keys
security-compliance-cli --serial-device /dev/ttyUSB0 check-ssh-keys --detailed

# Remove test keys
security-compliance-cli --serial-device /dev/ttyUSB0 uninstall-ssh-key --remove-temp-keys
```

#### Machine Detection
```bash
# Auto-detect platform and run appropriate tests
security-compliance-cli --host 192.168.0.36 detect

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
- **runtime_008**: Read-Only Filesystem Protection
- **runtime_009**: PCF2131 RTC Security (i.MX93 E-Ink)

### 🔧 Hardware Security Tests
- **hardware_001**: EdgeLock Enclave (ELE)
- **hardware_002**: Secure Enclave Status
- **hardware_003**: Hardware Root of Trust
- **hardware_004**: Crypto Hardware Acceleration (CAAM)
- **hardware_005**: Hardware RNG
- **hardware_006**: PCF2131 RTC Validation (i.MX93 E-Ink)

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

### 🐳 Container Security Tests
- **container_001**: Docker/Podman Security Configuration
- **container_002**: Container Image Security
- **container_003**: Runtime Security
- **container_004**: Network Isolation
- **container_005**: User Namespaces
- **container_006**: SELinux Contexts
- **container_007**: Seccomp Profiles

### 🔐 Certificate Management Tests
- **certificate_001**: X.509 Certificate Validation
- **certificate_002**: PKI Infrastructure Assessment
- **certificate_003**: Certificate Expiration Monitoring
- **certificate_004**: Certificate Chain Validation
- **certificate_005**: Certificate Revocation (CRL/OCSP)
- **certificate_006**: Secure Certificate Storage
- **certificate_007**: CA Certificate Management
- **certificate_008**: TLS Certificate Validation
- **certificate_009**: Certificate Rotation Mechanisms
- **certificate_010**: Certificate Compliance Standards

### 🏭 Production Hardening Tests
- **production_001**: Debug Interfaces Disabled
- **production_002**: Development Tools Removed
- **production_003**: Default Credentials Changed
- **production_004**: Unnecessary Services Disabled
- **production_005**: Production Logging Configured
- **production_006**: System Monitoring Enabled
- **production_007**: Backup Systems Active
- **production_008**: Security Updates Enabled
- **production_009**: Network Hardening Applied
- **production_010**: Filesystem Hardening Applied

## Configuration

### Command Line Options

```bash
security-compliance-cli [OPTIONS] <COMMAND>

🌐 SSH Communication:
  -H, --host <HOST>           Target IP address [default: 192.168.0.36]
  -p, --port <PORT>           Target SSH port [default: 22]
  -u, --user <USER>           SSH username [default: fio]
  -P, --password <PASSWORD>   SSH password
      --timeout <TIMEOUT>     Connection timeout [default: 30]

📺 Serial Communication (Linux/macOS):
      --serial-device <DEV>   Serial device path (e.g., /dev/ttyUSB0)
      --baud-rate <RATE>      Serial baud rate [default: 115200]
      --serial-username <U>   Serial login username
      --serial-password <P>   Serial login password

🖥️ Machine Detection:
  -m, --machine <MACHINE>     Target machine type [auto-detect]
                              [possible values: imx93-jaguar-eink, imx8mm-jaguar-sentai]

📊 Output Options:
  -f, --format <FORMAT>       Output format [possible values: human, json, junit, markdown, cra, red, pdf]
  -v, --verbose               Verbose output (can be used multiple times)
  -o, --output <OUTPUT>       Output file for results
  -c, --config <CONFIG>       Configuration file

Commands:
  test                Run security compliance tests
  list                List available tests
  detect              Detect target machine type and features
  validate            Validate configuration file
  install-ssh-key     Install SSH key via serial console
  uninstall-ssh-key   Remove SSH keys from target
  check-ssh-keys      Check installed SSH test keys
```

### Configuration File

Create a `config.toml` file for persistent settings:

```toml
[communication]
channel_type = "ssh"  # or "serial"
host = "192.168.0.36"
port = 22
user = "fio"
password = "fio"
timeout = 30
ssh_multiplex = true

# Serial configuration (Linux/macOS only)
serial_device = "/dev/ttyUSB0"
baud_rate = 115200
serial_username = "fio"
serial_password = "fio"
serial_login_prompt = "login:"
serial_password_prompt = "Password:"
serial_shell_prompt = "$ "

[machine]
auto_detect = true
machine_type = "imx93-jaguar-eink"  # optional override

[output]
format = "human"  # human, json, junit, markdown, cra, red, pdf
verbose = 1
colors = true

[tests]
suite = "all"
mode = "pre-production"
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
Tests: 64
Mode: Pre-Production

✅ boot_001 - Secure Boot Enabled: AHAB secure boot detected
✅ boot_002 - U-Boot Signature Verification: FIT image verification active
❌ runtime_001 - Filesystem Encryption (LUKS): No filesystem encryption detected
⚠️  network_001 - Open Network Ports: Some security concerns (8 ports, 1 risky)
✅ container_001 - Docker Security Configuration: Container security configured (2 features)
✅ certificate_001 - X.509 Validation: X.509 validation infrastructure ready

📊 Test Results Summary
======================

Overall Status: FAILED
Success Rate: 89.1%

📈 Statistics:
  Total Tests: 64
  ✅ Passed: 57
  ❌ Failed: 3
  ⚠️  Warnings: 4
  ⏭️  Skipped: 0
  💥 Errors: 0

⏱️  Duration: 78.5s

❌ Failed Tests:
  • runtime_001 - Filesystem Encryption (LUKS): No filesystem encryption detected
  • compliance_001 - CRA Data Protection (Article 11): CRA non-compliant (1/4 items)
```

### Verbose Mode Output

```
🔒 Security Compliance Testing
================================
Suite: All
Tests: 64
Mode: Pre-Production

✅ boot_001 - Secure Boot Enabled
   Purpose: Verifies that the hardware secure boot chain is properly enabled and functioning, ensuring only trusted firmware can execute during system startup
   Result: AHAB secure boot detected

✅ runtime_008 - Read-Only Filesystem Protection  
   Purpose: Ensures critical system directories are mounted read-only to prevent unauthorized modifications and enhance system integrity
   Result: Read-only filesystem properly configured (5 protected areas)
```

### JSON Format

```json
{
  "suite_name": "All",
  "test_mode": "PreProduction",
  "total_tests": 64,
  "passed": 57,
  "failed": 3,
  "warnings": 4,
  "skipped": 0,
  "errors": 0,
  "duration": {
    "secs": 78,
    "nanos": 500000000
  },
  "timestamp": "2025-10-07T10:30:00Z",
  "system_info": {
    "kernel_version": "6.1.70-lmp-standard",
    "uname": "Linux imx93-jaguar-eink 6.1.70-lmp-standard #1 SMP PREEMPT",
    "uptime": "up 2 days, 14:32",
    "memory_info": "total 1931 used 126 free 1447",
    "os_release": "ID=lmp-dynamicdevices-headless VERSION_ID=4.0.20-2156-94",
    "foundries_registration": "Not Registered",
    "wireguard_status": "Not Available"
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

# Run with verbose output for educational purposes
cargo run -- test --host 192.168.0.36 --verbose

# Cross-compile for ARM64 target
./build-aarch64.sh
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

### Supported Platforms
- **i.MX93 E-Ink Jaguar**: EdgeLock Enclave, CAAM, PCF2131 RTC
- **i.MX8MM Sentai Jaguar**: TrustZone, OP-TEE, CAAM
- **Generic ARM64**: Basic security testing

### System Requirements
- **Operating System**: Foundries.io Linux Micro Platform v95+
- **Network**: SSH access (port 22) or Serial console
- **Memory**: 512MB RAM minimum, 1GB storage
- **Serial**: USB-to-serial adapter for console access (Windows, Linux, macOS)

### Host Platform Support
- **Linux**: Full functionality (SSH + Serial)
- **macOS**: Full functionality (SSH + Serial)
- **Windows**: Full functionality (SSH + Serial)

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
- ✅ i.MX8MM TrustZone and OP-TEE
- ✅ Hardware root of trust
- ✅ Cryptographic acceleration (CAAM)
- ✅ Hardware random number generator
- ✅ PCF2131 RTC validation (E-Ink platform)
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

# Install SSH key via serial
security-compliance-cli --serial-device /dev/ttyUSB0 install-ssh-key

# Use verbose mode for debugging
security-compliance-cli test --verbose --host 192.168.0.36
```

**Serial Connection Issues**:
```bash
# Check serial device permissions
ls -la /dev/ttyUSB*
sudo usermod -a -G dialout $USER  # Add user to dialout group

# Test serial connection
security-compliance-cli --serial-device /dev/ttyUSB0 --verbose check-ssh-keys

# Try different baud rates
security-compliance-cli --serial-device /dev/ttyUSB0 --baud-rate 9600 test
```

**Windows Serial Support**:
```bash
# Windows now supports serial communication directly
security-compliance-cli --serial-device COM3 --serial-username fio test

# SSH remains available as an alternative
security-compliance-cli --host 192.168.0.36 --user fio test

# SSH key management works natively on Windows
security-compliance-cli --serial-device COM3 install-ssh-key --key-validity-hours 2
```

**Test Timeouts**:
```bash
# Increase timeout
security-compliance-cli test --timeout 60

# Run specific test suite only
security-compliance-cli test --test-suite boot

# Use machine-specific tests
security-compliance-cli --machine imx93-jaguar-eink test
```

## Support

- **Maintainer**: Alex J Lennon <alex@dynamicdevices.co.uk>
- **Company**: Dynamic Devices Ltd
- **Support**: info@dynamicdevices.co.uk
- **Issues**: [GitHub Issues](https://github.com/DynamicDevices/security-compliance-cli/issues)
- **Documentation**: [Project Wiki](https://github.com/DynamicDevices/security-compliance-cli/wiki)

## License

**Security Compliance CLI** - Hardware security testing for embedded Linux  
Copyright (C) 2025 Dynamic Devices Ltd

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

**Maintainer**: Alex J Lennon <alex@dynamicdevices.co.uk>  
**Support**: info@dynamicdevices.co.uk  
**Website**: https://www.dynamicdevices.co.uk

## Related Projects

- [eink-power-cli](https://github.com/DynamicDevices/eink-power-cli) - Power management CLI
- [meta-dynamicdevices](https://github.com/DynamicDevices/meta-dynamicdevices) - Yocto BSP layers
- [Foundries.io](https://foundries.io) - Linux Micro Platform
