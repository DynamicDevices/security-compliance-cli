/*
 * Security Compliance CLI - SSH Communication Channel
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::communication::{ChannelConfig, CommandOutput, CommunicationChannel};
use crate::error::{Error, Result};
use async_trait::async_trait;
use ssh2::Session;
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, info};

pub struct SshChannel {
    config: SshChannelConfig,
    session: Option<Session>,
    connected: bool,
}

#[derive(Debug, Clone)]
pub struct SshChannelConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub ssh_key_path: Option<String>,
    pub timeout: u32,
    pub ssh_multiplex: bool,
}

impl SshChannel {
    pub fn new(config: SshChannelConfig) -> Self {
        Self {
            config,
            session: None,
            connected: false,
        }
    }

    pub fn from_channel_config(config: ChannelConfig) -> Result<Self> {
        match config {
            ChannelConfig::Ssh {
                host,
                port,
                user,
                password,
                ssh_key_path,
                timeout,
                ssh_multiplex,
            } => Ok(Self::new(SshChannelConfig {
                host,
                port,
                user,
                password,
                ssh_key_path,
                timeout,
                ssh_multiplex,
            })),
            _ => Err(Error::Config("Invalid channel config for SSH".to_string())),
        }
    }

    fn try_key_auth(&self, session: &Session) -> Result<bool> {
        let key_paths = if let Some(key_path) = &self.config.ssh_key_path {
            // If a specific key is provided, only try that key to avoid "too many authentication failures"
            vec![key_path.clone()]
        } else {
            // Try common SSH key locations, including our test key
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            vec![
                "test_device_key".to_string(), // Our generated test key in current directory
                format!("{}/.ssh/test_device_key", home), // Test key in SSH directory
                format!("{}/.ssh/id_ed25519", home), // Prefer Ed25519 over RSA
                format!("{}/.ssh/id_rsa", home),
                format!("{}/.ssh/id_ecdsa", home),
                format!("{}/.ssh/id_dsa", home),
            ]
        };

        for key_path in key_paths {
            if Path::new(&key_path).exists() {
                debug!("Trying SSH key: {}", key_path);
                let public_key_path = format!("{}.pub", key_path);

                let result = if Path::new(&public_key_path).exists() {
                    session.userauth_pubkey_file(
                        &self.config.user,
                        Some(Path::new(&public_key_path)),
                        Path::new(&key_path),
                        None,
                    )
                } else {
                    session.userauth_pubkey_file(
                        &self.config.user,
                        None,
                        Path::new(&key_path),
                        None,
                    )
                };

                match result {
                    Ok(()) => {
                        info!("SSH key authentication successful with: {}", key_path);
                        return Ok(true);
                    }
                    Err(e) => {
                        debug!("SSH key authentication failed for {}: {}", key_path, e);

                        // If we have a specific key path and it fails, don't try others
                        // This prevents "too many authentication failures"
                        if self.config.ssh_key_path.is_some() {
                            debug!("Specific key failed, not trying additional keys to avoid authentication failures");
                            break;
                        }
                    }
                }
            }
        }

        Ok(false)
    }
}

#[async_trait]
impl CommunicationChannel for SshChannel {
    async fn connect(&mut self) -> Result<()> {
        info!(
            "Connecting to SSH {}:{}",
            self.config.host, self.config.port
        );

        let tcp = TcpStream::connect(format!("{}:{}", self.config.host, self.config.port))
            .map_err(|e| Error::SshConnection(format!("TCP connection failed: {}", e)))?;

        tcp.set_read_timeout(Some(Duration::from_secs(self.config.timeout as u64)))
            .map_err(|e| Error::SshConnection(format!("Failed to set read timeout: {}", e)))?;

        let mut session = Session::new()
            .map_err(|e| Error::SshConnection(format!("Failed to create SSH session: {}", e)))?;

        session.set_tcp_stream(tcp);
        session
            .handshake()
            .map_err(|e| Error::SshConnection(format!("SSH handshake failed: {}", e)))?;

        // Try key-based authentication first
        if !self.try_key_auth(&session)? {
            debug!("Key authentication failed, trying password authentication");
            session
                .userauth_password(&self.config.user, &self.config.password)
                .map_err(|e| Error::SshAuth(format!("Password authentication failed: {}", e)))?;
        }

        if !session.authenticated() {
            return Err(Error::SshAuth("Authentication failed".to_string()));
        }

        info!("SSH connection established successfully");
        self.session = Some(session);
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(session) = &mut self.session {
            session
                .disconnect(None, "Closing connection", None)
                .map_err(|e| Error::SshConnection(format!("Disconnect failed: {}", e)))?;
        }
        self.session = None;
        self.connected = false;
        info!("SSH connection closed");
        Ok(())
    }

    async fn execute_command(&mut self, command: &str) -> Result<CommandOutput> {
        self.execute_command_with_timeout(command, Duration::from_secs(60))
            .await
    }

    async fn execute_command_with_timeout(
        &mut self,
        command: &str,
        _timeout: Duration,
    ) -> Result<CommandOutput> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| Error::Communication("Not connected".to_string()))?;

        debug!("Executing SSH command: {}", command);

        let mut channel = session
            .channel_session()
            .map_err(|e| Error::CommandExecution(format!("Failed to create channel: {}", e)))?;

        channel
            .exec(command)
            .map_err(|e| Error::CommandExecution(format!("Failed to execute command: {}", e)))?;

        let mut stdout = String::new();
        channel
            .read_to_string(&mut stdout)
            .map_err(|e| Error::CommandExecution(format!("Failed to read stdout: {}", e)))?;

        let mut stderr = String::new();
        channel
            .stderr()
            .read_to_string(&mut stderr)
            .map_err(|e| Error::CommandExecution(format!("Failed to read stderr: {}", e)))?;

        channel
            .wait_close()
            .map_err(|e| Error::CommandExecution(format!("Failed to close channel: {}", e)))?;

        let exit_code = channel
            .exit_status()
            .map_err(|e| Error::CommandExecution(format!("Failed to get exit status: {}", e)))?;

        debug!("Command completed with exit code: {}", exit_code);

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_code,
        })
    }

    async fn is_connected(&self) -> bool {
        self.connected
    }

    fn description(&self) -> String {
        format!(
            "SSH connection to {}@{}:{}",
            self.config.user, self.config.host, self.config.port
        )
    }

    async fn upload_file(&mut self, local_path: &str, remote_path: &str) -> Result<()> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| Error::Communication("Not connected".to_string()))?;

        let local_file = std::fs::File::open(local_path).map_err(Error::Io)?;

        let metadata = local_file.metadata().map_err(Error::Io)?;

        let mut remote_file = session
            .scp_send(Path::new(remote_path), 0o644, metadata.len(), None)
            .map_err(|e| Error::Communication(format!("SCP upload failed: {}", e)))?;

        let mut local_file = std::fs::File::open(local_path).map_err(Error::Io)?;

        std::io::copy(&mut local_file, &mut remote_file)
            .map_err(|e| Error::Communication(format!("Failed to copy file: {}", e)))?;

        remote_file
            .send_eof()
            .map_err(|e| Error::Communication(format!("Failed to send EOF: {}", e)))?;

        remote_file
            .wait_eof()
            .map_err(|e| Error::Communication(format!("Failed to wait for EOF: {}", e)))?;

        remote_file
            .close()
            .map_err(|e| Error::Communication(format!("Failed to close remote file: {}", e)))?;

        remote_file
            .wait_close()
            .map_err(|e| Error::Communication(format!("Failed to wait for close: {}", e)))?;

        info!(
            "File uploaded successfully: {} -> {}",
            local_path, remote_path
        );
        Ok(())
    }

    async fn download_file(&mut self, remote_path: &str, local_path: &str) -> Result<()> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| Error::Communication("Not connected".to_string()))?;

        let (mut remote_file, _stat) = session
            .scp_recv(Path::new(remote_path))
            .map_err(|e| Error::Communication(format!("SCP download failed: {}", e)))?;

        let mut local_file = std::fs::File::create(local_path).map_err(Error::Io)?;

        std::io::copy(&mut remote_file, &mut local_file)
            .map_err(|e| Error::Communication(format!("Failed to copy file: {}", e)))?;

        remote_file
            .send_eof()
            .map_err(|e| Error::Communication(format!("Failed to send EOF: {}", e)))?;

        remote_file
            .wait_eof()
            .map_err(|e| Error::Communication(format!("Failed to wait for EOF: {}", e)))?;

        remote_file
            .close()
            .map_err(|e| Error::Communication(format!("Failed to close remote file: {}", e)))?;

        remote_file
            .wait_close()
            .map_err(|e| Error::Communication(format!("Failed to wait for close: {}", e)))?;

        info!(
            "File downloaded successfully: {} -> {}",
            remote_path, local_path
        );
        Ok(())
    }
}
