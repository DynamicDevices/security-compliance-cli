/*
 * Security Compliance CLI - Serial Communication Channel
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::communication::{ChannelConfig, CommandOutput, CommunicationChannel};
use crate::error::{Error, Result};
use async_trait::async_trait;
use bytes::BytesMut;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};
use tokio_serial::{SerialPortBuilderExt, SerialStream};
use tracing::{debug, info};

pub struct SerialChannel {
    config: SerialChannelConfig,
    port: Option<SerialStream>,
    connected: bool,
    logged_in: bool,
}

#[derive(Debug, Clone)]
pub struct SerialChannelConfig {
    pub device: String,
    pub baud_rate: u32,
    pub timeout: u32,
    pub login_prompt: Option<String>,
    pub password_prompt: Option<String>,
    pub shell_prompt: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl SerialChannel {
    pub fn new(config: SerialChannelConfig) -> Self {
        Self {
            config,
            port: None,
            connected: false,
            logged_in: false,
        }
    }

    pub fn from_channel_config(config: ChannelConfig) -> Result<Self> {
        match config {
            ChannelConfig::Serial {
                device,
                baud_rate,
                timeout,
                login_prompt,
                password_prompt,
                shell_prompt,
                username,
                password,
            } => Ok(Self::new(SerialChannelConfig {
                device,
                baud_rate,
                timeout,
                login_prompt,
                password_prompt,
                shell_prompt,
                username,
                password,
            })),
            _ => Err(Error::Config(
                "Invalid channel config for Serial".to_string(),
            )),
        }
    }

    async fn wait_for_prompt(
        &mut self,
        expected_prompt: &str,
        timeout_secs: u64,
    ) -> Result<String> {
        let port = self
            .port
            .as_mut()
            .ok_or_else(|| Error::Communication("Serial port not connected".to_string()))?;

        let mut buffer = BytesMut::new();
        let mut response = String::new();

        let result = timeout(Duration::from_secs(timeout_secs), async {
            loop {
                let mut temp_buf = [0u8; 1024];
                match port.read(&mut temp_buf).await {
                    Ok(n) if n > 0 => {
                        buffer.extend_from_slice(&temp_buf[..n]);
                        let text = String::from_utf8_lossy(&buffer);
                        response = text.to_string();

                        debug!("Serial received: {}", text.trim());

                        if text.contains(expected_prompt) {
                            return Ok(response.clone());
                        }
                    }
                    Ok(_) => {
                        // No data received, continue waiting
                        sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        return Err(Error::SerialConnection(format!("Read error: {}", e)));
                    }
                }
            }
        })
        .await;

        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::SerialConnection(format!(
                "Timeout waiting for prompt: {}",
                expected_prompt
            ))),
        }
    }

    async fn send_command(&mut self, command: &str) -> Result<()> {
        let port = self
            .port
            .as_mut()
            .ok_or_else(|| Error::Communication("Serial port not connected".to_string()))?;

        debug!("Sending serial command: {}", command);

        let command_with_newline = format!("{}\r\n", command);
        port.write_all(command_with_newline.as_bytes())
            .await
            .map_err(|e| Error::SerialConnection(format!("Failed to send command: {}", e)))?;

        port.flush()
            .await
            .map_err(|e| Error::SerialConnection(format!("Failed to flush: {}", e)))?;

        Ok(())
    }

    async fn login_if_needed(&mut self) -> Result<()> {
        if self.logged_in {
            return Ok(());
        }

        // Send a newline to trigger any prompt
        if let Some(port) = &mut self.port {
            port.write_all(b"\r\n")
                .await
                .map_err(|e| Error::SerialConnection(format!("Failed to send newline: {}", e)))?;
            port.flush()
                .await
                .map_err(|e| Error::SerialConnection(format!("Failed to flush: {}", e)))?;
        }

        sleep(Duration::from_millis(500)).await;

        // Check if we need to login
        let login_prompt = self.config.login_prompt.clone();
        let username = self.config.username.clone();
        let password_prompt = self.config.password_prompt.clone();
        let password = self.config.password.clone();
        let shell_prompt = self.config.shell_prompt.clone();

        if let Some(login_prompt) = login_prompt {
            if let Some(username) = username {
                info!("Waiting for login prompt: {}", login_prompt);
                self.wait_for_prompt(&login_prompt, 10).await?;

                self.send_command(&username).await?;

                if let Some(password_prompt) = password_prompt {
                    if let Some(password) = password {
                        info!("Waiting for password prompt: {}", password_prompt);
                        self.wait_for_prompt(&password_prompt, 10).await?;
                        self.send_command(&password).await?;
                    }
                }
            }
        }

        // Wait for shell prompt if specified
        if let Some(shell_prompt) = shell_prompt {
            info!("Waiting for shell prompt: {}", shell_prompt);
            self.wait_for_prompt(&shell_prompt, 10).await?;
        } else {
            // Give some time for the system to be ready
            sleep(Duration::from_secs(2)).await;
        }

        self.logged_in = true;
        info!("Serial login completed successfully");
        Ok(())
    }
}

#[async_trait]
impl CommunicationChannel for SerialChannel {
    async fn connect(&mut self) -> Result<()> {
        info!(
            "Connecting to serial device: {} at {} baud",
            self.config.device, self.config.baud_rate
        );

        let port = tokio_serial::new(&self.config.device, self.config.baud_rate)
            .timeout(Duration::from_secs(self.config.timeout as u64))
            .open_native_async()
            .map_err(|e| Error::SerialConnection(format!("Failed to open serial port: {}", e)))?;

        self.port = Some(port);
        self.connected = true;

        // Attempt login if credentials are provided
        self.login_if_needed().await?;

        info!("Serial connection established successfully");
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if let Some(_port) = self.port.take() {
            // Port will be dropped automatically
        }
        self.connected = false;
        self.logged_in = false;
        info!("Serial connection closed");
        Ok(())
    }

    async fn execute_command(&mut self, command: &str) -> Result<CommandOutput> {
        self.execute_command_with_timeout(command, Duration::from_secs(30))
            .await
    }

    async fn execute_command_with_timeout(
        &mut self,
        command: &str,
        timeout_duration: Duration,
    ) -> Result<CommandOutput> {
        if !self.connected {
            return Err(Error::Communication(
                "Serial port not connected".to_string(),
            ));
        }

        // Ensure we're logged in
        self.login_if_needed().await?;

        debug!("Executing serial command: {}", command);

        // Send the command
        self.send_command(command).await?;

        // Wait for command output
        let port = self
            .port
            .as_mut()
            .ok_or_else(|| Error::Communication("Serial port not connected".to_string()))?;

        let mut buffer = BytesMut::new();
        let mut stdout = String::new();

        let result = timeout(timeout_duration, async {
            let mut command_echo_seen = false;
            let shell_prompt = self
                .config
                .shell_prompt
                .clone()
                .unwrap_or_else(|| "# ".to_string());

            loop {
                let mut temp_buf = [0u8; 1024];
                match port.read(&mut temp_buf).await {
                    Ok(n) if n > 0 => {
                        buffer.extend_from_slice(&temp_buf[..n]);
                        let text = String::from_utf8_lossy(&buffer);

                        // Skip the command echo (first line)
                        if !command_echo_seen {
                            if text.contains('\n') {
                                let lines: Vec<&str> = text.lines().collect();
                                if lines.len() > 1 {
                                    // Skip first line (command echo), keep the rest
                                    stdout = lines[1..].join("\n");
                                    command_echo_seen = true;
                                }
                            }
                        } else {
                            stdout = text.to_string();
                        }

                        // Check if we've reached the shell prompt (command completed)
                        if text.ends_with(&shell_prompt) || text.contains(&shell_prompt) {
                            // Remove the shell prompt from the output
                            if let Some(pos) = stdout.rfind(&shell_prompt) {
                                stdout.truncate(pos);
                            }
                            stdout = stdout.trim().to_string();
                            break;
                        }
                    }
                    Ok(_) => {
                        // No data received, continue waiting
                        sleep(Duration::from_millis(100)).await;
                    }
                    Err(e) => {
                        return Err(Error::SerialConnection(format!("Read error: {}", e)));
                    }
                }
            }
            Ok(())
        })
        .await;

        match result {
            Ok(Ok(())) => {
                debug!("Serial command completed successfully");
                Ok(CommandOutput {
                    stdout,
                    stderr: String::new(), // Serial doesn't separate stderr
                    exit_code: 0,          // We assume success if we got output
                })
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(Error::CommandExecution(format!(
                "Command timeout after {:?}",
                timeout_duration
            ))),
        }
    }

    async fn is_connected(&self) -> bool {
        self.connected
    }

    fn description(&self) -> String {
        format!(
            "Serial connection to {} at {} baud",
            self.config.device, self.config.baud_rate
        )
    }

    // File operations are not supported over serial
    async fn upload_file(&mut self, _local_path: &str, _remote_path: &str) -> Result<()> {
        Err(Error::Unsupported(
            "File upload not supported over serial connection".to_string(),
        ))
    }

    async fn download_file(&mut self, _remote_path: &str, _local_path: &str) -> Result<()> {
        Err(Error::Unsupported(
            "File download not supported over serial connection".to_string(),
        ))
    }
}
