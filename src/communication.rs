/*
 * Security Compliance CLI - Communication Channel Abstraction
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::error::Result;
use async_trait::async_trait;
use std::time::Duration;

/// Output from executing a command
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Abstract communication channel for executing commands on target systems
#[async_trait]
pub trait CommunicationChannel: Send + Sync {
    /// Connect to the target system
    async fn connect(&mut self) -> Result<()>;

    /// Disconnect from the target system
    async fn disconnect(&mut self) -> Result<()>;

    /// Execute a command and return the output
    async fn execute_command(&mut self, command: &str) -> Result<CommandOutput>;

    /// Execute a command with a custom timeout
    async fn execute_command_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<CommandOutput>;

    /// Check if the connection is still active
    async fn is_connected(&self) -> bool;

    /// Get a description of the communication channel
    fn description(&self) -> String;

    /// Upload a file to the target system (optional, not all channels support this)
    async fn upload_file(&mut self, _local_path: &str, _remote_path: &str) -> Result<()> {
        Err(crate::error::Error::Unsupported(
            "File upload not supported by this communication channel".to_string(),
        ))
    }

    /// Download a file from the target system (optional, not all channels support this)
    async fn download_file(&mut self, _remote_path: &str, _local_path: &str) -> Result<()> {
        Err(crate::error::Error::Unsupported(
            "File download not supported by this communication channel".to_string(),
        ))
    }
}

/// Configuration for different communication channel types
#[derive(Debug, Clone)]
pub enum ChannelConfig {
    Ssh {
        host: String,
        port: u16,
        user: String,
        password: String,
        ssh_key_path: Option<String>,
        timeout: u32,
        ssh_multiplex: bool,
    },
    Serial {
        device: String,
        baud_rate: u32,
        timeout: u32,
        login_prompt: Option<String>,
        password_prompt: Option<String>,
        shell_prompt: Option<String>,
        username: Option<String>,
        password: Option<String>,
    },
}

impl ChannelConfig {
    pub fn channel_type(&self) -> &'static str {
        match self {
            ChannelConfig::Ssh { .. } => "ssh",
            ChannelConfig::Serial { .. } => "serial",
        }
    }
}
