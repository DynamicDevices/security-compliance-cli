/*
 * Security Compliance CLI - Command Line Interface
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "security-compliance-cli")]
#[command(about = "🔒 Security Compliance Testing Tool for Embedded Linux Systems\n\nThis tool helps technicians verify that embedded devices meet security standards\nlike EU Cyber Resilience Act (CRA) and UK CE RED requirements.")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "Alex J Lennon <ajlennon@dynamicdevices.co.uk>")]
#[command(long_about = "🔒 SECURITY COMPLIANCE TESTING TOOL\n\nThis tool performs automated security compliance testing on embedded Linux devices.\nIt can connect via SSH (network) or Serial (direct connection) to run comprehensive\nsecurity tests and generate compliance reports for certification.\n\n📋 WHAT IT TESTS:\n• Boot security (secure boot, signatures)\n• Hardware security (encryption, secure storage)\n• Network security (firewall, protocols)\n• Runtime security (file permissions, services)\n• Compliance requirements (CRA, RED standards)\n\n📊 REPORT FORMATS:\n• Human-readable console output\n• PDF reports for certification\n• JSON/XML for automation\n• CRA/RED compliance reports\n\n🔌 CONNECTION METHODS:\n• SSH: For networked devices (--host)\n• Serial: For direct connection (--serial-device)\n\n💡 TIP: Start with 'detect' command to identify your device type")]
pub struct Cli {
    /// 🌐 Target device IP address (for SSH/network connections)
    /// 
    /// Use this when your device is connected to the network.
    /// Example: 192.168.1.100, 10.0.0.50
    #[arg(short = 'H', long, default_value = "192.168.0.36")]
    pub host: String,

    /// 🔌 SSH port number (usually 22)
    /// 
    /// Standard SSH port is 22. Change if your device uses a different port.
    #[arg(short, long, default_value = "22")]
    pub port: u16,

    /// 👤 SSH username (device login name)
    /// 
    /// Common usernames: root, admin, pi, fio
    #[arg(short, long, default_value = "fio")]
    pub user: String,

    /// 🔑 SSH password (device login password)
    /// 
    /// Use password authentication. For better security, use SSH keys instead.
    #[arg(short = 'P', long, default_value = "fio")]
    pub password: String,

    /// 🗝️ SSH private key file (more secure than password)
    /// 
    /// Path to your SSH private key file (e.g., ~/.ssh/id_rsa).
    /// If not specified, will try common key locations automatically.
    #[arg(short = 'i', long)]
    pub identity_file: Option<PathBuf>,

    /// 📡 Serial device path (for direct cable connection)
    /// 
    /// Use this instead of SSH when device has no network.
    /// Linux: /dev/ttyUSB0, /dev/ttyACM0
    /// Windows: COM1, COM3
    /// macOS: /dev/tty.usbserial-*
    #[arg(short = 'S', long)]
    pub serial_device: Option<String>,

    /// ⚡ Serial communication speed (baud rate)
    /// 
    /// Must match your device's serial console speed.
    /// Common rates: 9600, 38400, 115200
    #[arg(short = 'B', long, default_value = "115200")]
    pub baud_rate: u32,

    /// 👤 Serial login username (if device requires login)
    /// 
    /// Leave empty if device doesn't need login or is already logged in.
    #[arg(long)]
    pub serial_username: Option<String>,

    /// 🔑 Serial login password (if device requires login)
    /// 
    /// Leave empty if device doesn't need password or uses key authentication.
    #[arg(long)]
    pub serial_password: Option<String>,

    /// 📝 Text to wait for when device asks for username
    /// 
    /// The prompt your device shows when asking for login name.
    #[arg(long, default_value = "login:")]
    pub serial_login_prompt: String,

    /// 📝 Text to wait for when device asks for password
    /// 
    /// The prompt your device shows when asking for password.
    #[arg(long, default_value = "Password:")]
    pub serial_password_prompt: String,

    /// 📝 Text that shows when device is ready for commands
    /// 
    /// The command prompt (e.g., "# ", "$ ", "root@device:~# ").
    /// Tool waits for this before running tests.
    #[arg(long, default_value = "# ")]
    pub serial_shell_prompt: String,

    /// ⏱️ Connection timeout in seconds
    /// 
    /// How long to wait for device to respond before giving up.
    /// Increase for slow devices or networks.
    #[arg(long, default_value = "30")]
    pub timeout: u64,

    /// 📄 Report output format
    /// 
    /// Choose how you want the test results presented:
    /// • human: Easy-to-read colored output (good for technicians)
    /// • pdf: Professional report for certification/documentation
    /// • json: Machine-readable data for automation
    /// • cra: EU Cyber Resilience Act compliance report
    /// • red: UK CE RED compliance report
    #[arg(short = 'f', long, default_value = "human")]
    pub format: OutputFormat,

    /// 🔍 Verbose output (use -v, -vv, or -vvv for more detail)
    /// 
    /// Shows more information about what the tool is doing:
    /// • -v: Basic progress information
    /// • -vv: Detailed test execution
    /// • -vvv: Full debug information
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// 📋 Configuration file (saves typing common options)
    /// 
    /// Load settings from a TOML file instead of typing them each time.
    /// Example: config.toml with your device settings.
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// 💾 Save results to file
    /// 
    /// Write the test results to a file instead of just showing on screen.
    /// File format depends on --format option.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// 🎯 Target device type (helps run appropriate tests)
    /// 
    /// Specify your exact device model for targeted testing.
    /// Use 'detect' command first to identify your device automatically.
    #[arg(short = 'm', long)]
    pub machine: Option<MachineType>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// 🧪 Run security compliance tests on your device
    /// 
    /// This is the main command that connects to your device and runs security tests.
    /// Results show if your device meets security standards for certification.
    /// 
    /// QUICK START:
    /// • Network device: test --host 192.168.1.100
    /// • Serial device: test --serial-device /dev/ttyUSB0
    /// • Auto-detect: test (uses default settings)
    Test {
        /// 📦 Which group of tests to run
        /// 
        /// Different test suites check different security aspects:
        /// • all: Complete security audit (recommended for certification)
        /// • hardware: Check secure boot, encryption, hardware security
        /// • network: Test firewall, secure protocols, network security
        /// • compliance: EU CRA and UK RED specific requirements
        /// • boot: Verify secure boot and trusted execution
        /// • runtime: Check running services and file permissions
        #[arg(short, long, default_value = "all")]
        test_suite: TestSuite,

        /// 🎚️ How strict should the testing be?
        /// 
        /// • pre-production: Allows warnings, good for development
        /// • production: Strict checking required for final certification
        #[arg(short, long, default_value = "pre-production")]
        mode: TestMode,

        /// ⏭️ Keep testing even if some tests fail
        /// 
        /// Normally testing stops at first failure. Use this to see all issues.
        #[arg(long)]
        continue_on_failure: bool,

        /// 📊 Create detailed report with extra information
        /// 
        /// Includes technical details, remediation steps, and compliance mapping.
        #[arg(long)]
        detailed_report: bool,
    },
    /// 📋 Show all available tests (what can be checked)
    /// 
    /// Lists all security tests this tool can perform, organized by category.
    /// Useful to understand what aspects of security will be verified.
    List,

    /// ✅ Check if a configuration file is valid
    /// 
    /// Verifies your config file has correct syntax and valid settings
    /// before running tests. Helps catch configuration errors early.
    Validate {
        /// 📄 Path to the configuration file to check
        config_file: PathBuf,
    },

    /// 🔍 Automatically identify your device type and capabilities
    /// 
    /// Connects to your device and determines:
    /// • Device model and hardware type
    /// • Available security features
    /// • Recommended test suites
    /// 
    /// Run this first if you're unsure about your device specifications.
    Detect,
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    /// 👤 Easy-to-read colored output (recommended for technicians)
    Human,
    /// 🤖 Machine-readable structured data (for automation)
    Json,
    /// 🧪 JUnit XML format (for CI/CD systems like Jenkins)
    Junit,
    /// 📝 Markdown format (for documentation and reports)
    Markdown,
    /// 🇪🇺 EU Cyber Resilience Act compliance report
    Cra,
    /// 🇬🇧 UK CE RED (Radio Equipment Directive) compliance report
    Red,
    /// 📄 Professional PDF report (for certification bodies)
    Pdf,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum TestMode {
    /// 🔧 Development/testing mode (allows warnings, good for debugging)
    PreProduction,
    /// 🏭 Final certification mode (strict compliance, no warnings allowed)
    Production,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum TestSuite {
    /// 🎯 Complete security audit (all tests - recommended for certification)
    All,
    /// 🔐 Boot security (secure boot, signatures, trusted execution)
    Boot,
    /// ⚡ Runtime security (services, permissions, file system)
    Runtime,
    /// 🔒 Hardware security (encryption, secure storage, TPM)
    Hardware,
    /// 🌐 Network security (firewall, protocols, wireless)
    Network,
    /// 📋 Compliance requirements (CRA, RED, certification standards)
    Compliance,
    /// 📦 Container security (Docker, containerd, isolation)
    Container,
    /// 🎫 Certificate management (PKI, SSL/TLS, key storage)
    Certificate,
    /// 🏭 Production hardening (final deployment checks)
    Production,
    /// ⚙️ Custom test suite (defined in configuration file)
    Custom,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum MachineType {
    /// 📱 i.MX93 Jaguar E-Ink platform (e-paper display devices)
    Imx93JaguarEink,
    /// 🎮 i.MX8MM Jaguar Sentai platform (multimedia/gaming devices)
    Imx8mmJaguarSentai,
}
