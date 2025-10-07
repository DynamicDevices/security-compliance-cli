/*
 * Security Compliance CLI - Command Line Interface
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "security-compliance-cli")]
#[command(about = "Security compliance testing for Dynamic Devices embedded systems")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "Alex J Lennon <ajlennon@dynamicdevices.co.uk>")]
pub struct Cli {
    /// Target IP address
    #[arg(short = 'H', long, default_value = "192.168.0.36")]
    pub host: String,

    /// Target SSH port
    #[arg(short, long, default_value = "22")]
    pub port: u16,

    /// SSH username
    #[arg(short, long, default_value = "fio")]
    pub user: String,

    /// SSH password
    #[arg(short = 'P', long, default_value = "fio")]
    pub password: String,

    /// SSH private key file path (if not specified, tries default locations)
    #[arg(short = 'i', long)]
    pub identity_file: Option<PathBuf>,

    /// SSH connection timeout in seconds
    #[arg(long, default_value = "30")]
    pub timeout: u64,

    /// Output format
    #[arg(short = 'f', long, default_value = "human")]
    pub format: OutputFormat,

    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Output file for results
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run security compliance tests
    Test {
        /// Test suite to run
        #[arg(short, long, default_value = "all")]
        test_suite: TestSuite,

        /// Testing mode (pre-production or production)
        #[arg(short, long, default_value = "pre-production")]
        mode: TestMode,

        /// Continue on test failure
        #[arg(long)]
        continue_on_failure: bool,

        /// Generate detailed report
        #[arg(long)]
        detailed_report: bool,
    },
    /// List available tests
    List,
    /// Validate configuration file
    Validate {
        /// Configuration file to validate
        config_file: PathBuf,
    },
}

#[derive(Clone, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable output with colors and progress
    Human,
    /// JSON structured output
    Json,
    /// JUnit XML format for CI integration
    Junit,
    /// Markdown report format
    Markdown,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum TestMode {
    /// Pre-production mode (less strict, allows warnings)
    PreProduction,
    /// Production mode (strict compliance checking)
    Production,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum TestSuite {
    /// Run all security compliance tests
    All,
    /// Boot security tests (secure boot, signatures)
    Boot,
    /// Runtime security tests (firewall, encryption)
    Runtime,
    /// Hardware security tests (secure enclave, TPM)
    Hardware,
    /// Network security tests
    Network,
    /// Compliance tests (CRA, RED specific)
    Compliance,
    /// Container security tests
    Container,
    /// Certificate management tests
    Certificate,
    /// Production hardening tests
    Production,
    /// Custom test suite from config
    Custom,
}
