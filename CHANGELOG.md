# Changelog

All notable changes to the Security Compliance CLI project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2025-10-07

### 🎉 Latest Improvements

#### Enhanced Documentation
- **Updated README.md** with latest features including verbose mode examples
- **Enhanced CONTEXT.md** with recent improvements and current implementation status
- **Comprehensive project documentation** reflecting all 65 tests and educational features
- **Updated examples** showing verbose output and educational capabilities

#### Educational Features Expansion
- **Verbose mode examples** in documentation showing educational output
- **Enhanced test descriptions** in README with all current test categories
- **Better user guidance** for understanding security testing concepts
- **Improved onboarding** with clearer setup instructions

#### System Information Enhancements
- **Updated JSON output examples** with current system information format
- **Enhanced system info display** showing Foundries.io LMP details
- **Better target platform identification** in documentation
- **Current runtime results** reflecting real system testing

### 📚 Documentation Updates

#### README.md Improvements
- **Added verbose mode usage examples** (-v and -vv flags)
- **Updated test suite listings** with runtime_008 and latest tests
- **Enhanced JSON output examples** with current system information
- **Better educational guidance** for security testing

#### CONTEXT.md Enhancements
- **Added recent major improvements section** detailing v0.3.0 features
- **Updated test count** from 64 to 65 tests
- **Enhanced implementation status** with educational features
- **Better version tracking** and feature documentation

#### Project Structure
- **Improved documentation organization** with docs/ folder
- **Enhanced script organization** with scripts/ folder
- **Better separation of concerns** in documentation structure
- **Clearer project navigation** and file organization

---

## [0.3.0] - 2025-10-07

### 🎉 Major Features Added

#### Verbose Mode with Test Descriptions
- **Added comprehensive verbose mode** (`-v`, `-vv`) that displays detailed test purposes and categories
- **Enhanced all 64 test descriptions** with meaningful explanations of what each test validates and why it's important for security
- **Educational output** helps users understand security testing concepts and requirements
- **Two verbosity levels**: `-v` shows test purposes, `-vv` adds category information

#### Improved i.MX93 Support
- **Enhanced secure boot detection** for i.MX93 EdgeLock Enclave (ELE) systems
- **Fixed kernel signature verification** to properly detect hardware-based secure boot
- **Improved boot chain verification** to recognize ELE, U-Boot FIT signatures, and factory signing
- **Better hardware security detection** for CAAM crypto acceleration and hardware RNG

#### Enhanced System Information
- **Added OS release information** to test results summary
- **Improved system info display** with parsed OS details from `/etc/os-release`
- **Better target system identification** in all output formats

### 🔧 Test Improvements

#### Boot Security Tests
- **Fixed `boot_003` kernel signature verification** - now properly detects i.MX93 ELE-based verification
- **Enhanced `boot_007` boot chain verification** - recognizes multiple verification components
- **Updated `boot_005` and `boot_006`** - TF-A and OP-TEE tests now fail when missing (as they should be present)
- **Improved secure boot detection** with better ELE status checking and warnings for missing management tools

#### Test Coverage Expansion
- **Container Security Tests (7 tests)**: Docker/Podman security, image scanning, runtime isolation
- **Certificate Management Tests (10 tests)**: X.509 validation, PKI infrastructure, certificate lifecycle
- **Production Hardening Tests (10 tests)**: Debug interface lockdown, credential management, system hardening
- **Enhanced existing test suites** with more comprehensive checks

### 🏗️ Architecture Improvements

#### Test Framework Redesign
- **Resolved async trait compatibility issues** with enum-based test registry design
- **Improved test execution flow** with better error handling and status reporting
- **Enhanced test categorization** and filtering capabilities
- **Better separation of concerns** between test logic and execution framework

#### Code Quality
- **Fixed all compiler warnings** and unused imports
- **Improved error handling** throughout the codebase
- **Better documentation** and code comments
- **Enhanced type safety** with proper derive attributes

### 📊 Results and Statistics

#### Performance Improvements
- **Increased boot test success rate** from ~28% to 71.4%
- **Total test count** expanded from 27 to 64 tests
- **Better test categorization** across 8 security domains
- **More accurate security posture assessment**

#### Output Enhancements
- **Improved human-readable output** with better formatting and colors
- **Enhanced JSON output** with complete system information
- **Better error messages** and diagnostic information
- **More informative test result summaries**

### 🛠️ Bug Fixes

#### Critical Fixes
- **Fixed async trait object compatibility** that was preventing compilation
- **Resolved lifetime issues** in test implementations
- **Fixed missing derive attributes** causing serialization errors
- **Corrected CLI argument parsing** for global options

#### Test-Specific Fixes
- **Fixed kernel signature verification** false negatives on i.MX93 systems
- **Improved secure boot detection** to handle ELE-specific indicators
- **Enhanced boot chain verification** to recognize hardware-based security
- **Better handling of system-specific security architectures**

### 📚 Documentation

#### Enhanced Documentation
- **Updated README.md** with new test categories and usage examples
- **Comprehensive CONTEXT.md** with detailed project architecture
- **Added troubleshooting guides** for common issues
- **Improved CLI help text** and usage examples

#### Security Guides
- **Created ENABLE_AUDIT_LOGGING.md** with step-by-step audit setup
- **Added SECURITY_FIXES.md** with recommended security improvements
- **Enhanced hardware-specific documentation** for i.MX93 systems

### ⚠️ Breaking Changes

#### Test Behavior Changes
- **TF-A and OP-TEE tests now fail** when components are missing (previously skipped)
- **More strict compliance checking** in production mode
- **Enhanced validation** may flag previously passing systems

#### Configuration Changes
- **Updated test configuration format** with new test categories
- **Enhanced output configuration** options
- **New testing mode parameters**

### 🔄 Migration Guide

#### From v0.2.0 to v0.3.0
1. **Update test configurations** to include new test categories if using custom configs
2. **Review TF-A and OP-TEE test results** - these now fail instead of skip when missing
3. **Update CI/CD pipelines** to handle new test categories and verbose output options
4. **Check system requirements** for new hardware-specific tests

### 🎯 Target Platform Support

#### Enhanced Platform Support
- **i.MX93 EdgeLock Enclave** - Full support for ELE-based secure boot
- **ARM Cortex-A55** - Optimized for target architecture
- **Foundries.io Linux Micro Platform** - Native LMP integration
- **Yocto/Bitbake** - Enhanced build system integration

#### Hardware Security Features
- **EdgeLock Enclave (ELE)** - Hardware security module support
- **CAAM Crypto Acceleration** - Hardware crypto detection and configuration
- **Hardware RNG** - True random number generator validation
- **Factory Signing** - Production key management verification

### 🚀 Performance Metrics

#### Test Execution
- **Average test suite runtime**: ~3-4 seconds
- **Parallel test execution** capabilities
- **Efficient SSH connection reuse**
- **Optimized command execution** with proper timeouts

#### Resource Usage
- **Memory efficient** test execution
- **Minimal network overhead** with connection multiplexing  
- **Optimized binary size** with LTO and strip optimizations
- **Fast startup time** with optimized dependency loading

---

## [0.2.0] - 2025-10-06

### Added
- Initial comprehensive security testing framework
- Support for boot, hardware, network, runtime, and compliance tests
- Multiple output formats (human, JSON, JUnit XML, Markdown)
- SSH-based remote testing capabilities
- Configuration file support
- Basic i.MX93 EdgeLock Enclave detection

### Fixed
- Basic test framework implementation
- SSH connection handling
- Output formatting and display

---

## [0.1.0] - 2025-10-05

### Added
- Initial project structure
- Basic CLI framework with clap
- SSH client implementation
- Core test trait definitions
- Basic configuration management

---

## Unreleased

### Planned Features
- **Web-based dashboard** for test results visualization
- **Automated remediation suggestions** for failed tests
- **Integration with security scanners** (Trivy, Grype, etc.)
- **Custom test plugin system** for extensibility
- **Historical trend analysis** and reporting
- **SBOM (Software Bill of Materials)** integration
- **Compliance framework mapping** (NIST, ISO 27001, etc.)
- **Container registry integration** for image scanning
- **Kubernetes security testing** capabilities
- **Cloud security assessment** features

### Technical Debt
- **Refactor test execution engine** for better parallelization
- **Improve error handling** and recovery mechanisms
- **Enhance logging and debugging** capabilities
- **Add comprehensive unit tests** for all test modules
- **Performance optimization** for large-scale deployments
- **Memory usage optimization** for resource-constrained environments

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## Support

For support, please contact [ajlennon@dynamicdevices.co.uk](mailto:ajlennon@dynamicdevices.co.uk) or create an issue on GitHub.
