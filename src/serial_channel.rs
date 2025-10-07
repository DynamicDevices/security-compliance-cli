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
use tracing::{debug, info, warn};

/// Remove ANSI escape sequences from text for proper terminal emulation
fn strip_ansi_codes(text: &str) -> String {
    // Simple regex-like approach to remove ANSI escape sequences
    let mut result = String::new();
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Found escape sequence, skip until we find the end
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                              // Skip until we find a letter (end of ANSI sequence)
                for next_ch in chars.by_ref() {
                    if next_ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

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
                        let raw_text = String::from_utf8_lossy(&buffer);
                        let clean_text = strip_ansi_codes(&raw_text);
                        response = clean_text.clone();

                        debug!(
                            "Serial RX: {:?} -> {:?} (looking for: {:?})",
                            raw_text.trim(),
                            clean_text.trim(),
                            expected_prompt
                        );

                        if clean_text.contains(expected_prompt) {
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

        debug!("Serial TX: {:?}", command);

        let command_with_newline = format!("{}\r\n", command);
        debug!("Serial TX (with newline): {:?}", command_with_newline);
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

        // Send Ctrl-C and newlines to break out of any running process and get a clean prompt
        if let Some(port) = &mut self.port {
            debug!("Sending Ctrl-C to break out of any running process");
            port.write_all(&[3]) // Ctrl-C
                .await
                .map_err(|e| Error::SerialConnection(format!("Failed to send Ctrl-C: {}", e)))?;

            sleep(Duration::from_millis(100)).await;
            // Try different line endings to wake up the device
            for (i, line_ending) in [b"\r\n".as_slice(), b"\n".as_slice(), b"\r".as_slice()]
                .iter()
                .enumerate()
            {
                debug!("Sending line ending attempt {}: {:?}", i + 1, line_ending);
                port.write_all(line_ending).await.map_err(|e| {
                    Error::SerialConnection(format!("Failed to send newline: {}", e))
                })?;
                port.flush()
                    .await
                    .map_err(|e| Error::SerialConnection(format!("Failed to flush: {}", e)))?;

                // Wait a bit and try to read any response
                sleep(Duration::from_millis(500)).await;

                // Try to read any immediate response
                let mut temp_buf = [0u8; 1024];
                match port.try_read(&mut temp_buf) {
                    Ok(n) if n > 0 => {
                        let raw_response = String::from_utf8_lossy(&temp_buf[..n]);
                        let clean_response = strip_ansi_codes(&raw_response);
                        info!(
                            "Received after line ending {}: {:?} -> {:?}",
                            i + 1,
                            raw_response.trim(),
                            clean_response.trim()
                        );

                        // Check if we can see any shell-like prompt ($ or #) - be flexible
                        if clean_response.contains('$') || clean_response.contains('#') {
                            info!("Shell prompt detected in response, assuming ready");
                            self.logged_in = true;
                            return Ok(());
                        }
                    }
                    _ => {
                        debug!("No immediate response to line ending {}", i + 1);
                    }
                }
            }
        }

        sleep(Duration::from_millis(500)).await;

        // Check if we need to login
        let login_prompt = self.config.login_prompt.clone();
        let username = self.config.username.clone();
        let password_prompt = self.config.password_prompt.clone();
        let password = self.config.password.clone();
        let shell_prompt = self.config.shell_prompt.clone();

        // If no username is configured, assume we're already logged in or don't need login
        if username.is_none() {
            info!("No username configured, assuming shell is ready");
            self.logged_in = true;
            return Ok(());
        }

        // Try to wait for shell prompt first (maybe we're already logged in)
        if let Some(shell_prompt) = shell_prompt.clone() {
            debug!("Checking if already at shell prompt: {}", shell_prompt);
            match self.wait_for_prompt(&shell_prompt, 3).await {
                Ok(_) => {
                    info!("Already at shell prompt, no login needed");
                    self.logged_in = true;
                    return Ok(());
                }
                Err(_) => {
                    debug!("Not at shell prompt, checking for login prompt");
                }
            }
        }

        if let Some(login_prompt) = login_prompt {
            if let Some(username) = username {
                info!("Waiting for login prompt: {}", login_prompt);
                // Use a shorter timeout since we might not need to login
                match self.wait_for_prompt(&login_prompt, 5).await {
                    Ok(_) => {
                        info!("Login prompt found, proceeding with login");
                        self.send_command(&username).await?;

                        if let Some(password_prompt) = password_prompt {
                            if let Some(password) = password {
                                info!("Waiting for password prompt: {}", password_prompt);
                                self.wait_for_prompt(&password_prompt, 10).await?;
                                self.send_command(&password).await?;
                            }
                        }
                    }
                    Err(_) => {
                        info!("No login prompt found, assuming shell is ready");
                        self.logged_in = true;
                        return Ok(());
                    }
                }
            }
        }

        // Wait for shell prompt if specified, otherwise assume we're ready
        if let Some(shell_prompt) = shell_prompt {
            info!("Waiting for shell prompt: {}", shell_prompt);
            match self.wait_for_prompt(&shell_prompt, 10).await {
                Ok(_) => {
                    info!("Shell prompt detected");
                }
                Err(_) => {
                    // Be more forgiving - maybe the prompt is different than expected
                    warn!("Expected shell prompt not found, but assuming shell is ready");
                }
            }
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
            .data_bits(tokio_serial::DataBits::Eight)
            .parity(tokio_serial::Parity::None)
            .stop_bits(tokio_serial::StopBits::One)
            .flow_control(tokio_serial::FlowControl::None) // Disable hardware handshaking
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

        debug!(
            "Executing serial command with timeout: {} (timeout: {}s)",
            command,
            timeout_duration.as_secs()
        );

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
                .unwrap_or_else(|| "$ ".to_string()); // Default to $ instead of #

            debug!("Looking for shell prompt: {:?}", shell_prompt);

            loop {
                let mut temp_buf = [0u8; 1024];
                match port.read(&mut temp_buf).await {
                    Ok(n) if n > 0 => {
                        buffer.extend_from_slice(&temp_buf[..n]);
                        let raw_text = String::from_utf8_lossy(&buffer);
                        let clean_text = strip_ansi_codes(&raw_text);

                        debug!(
                            "Serial RX (command output): {:?} -> {:?}",
                            raw_text.trim(),
                            clean_text.trim()
                        );

                        // Skip the command echo (first line)
                        if !command_echo_seen {
                            if clean_text.contains('\n') {
                                let lines: Vec<&str> = clean_text.lines().collect();
                                // Find the line that contains our command (echo)
                                let mut start_index = 0;
                                for (i, line) in lines.iter().enumerate() {
                                    if line.trim().contains(command.trim())
                                        || line.trim().ends_with(command.trim())
                                    {
                                        start_index = i + 1; // Start after the echo line
                                        break;
                                    }
                                }

                                if start_index < lines.len() {
                                    stdout = lines[start_index..].join("\n");
                                    command_echo_seen = true;
                                    debug!("Command echo stripped, remaining output: {:?}", stdout);
                                } else {
                                    // No echo found yet, wait for more data
                                    continue;
                                }
                            }
                        } else {
                            // We've already seen the echo, accumulate the rest
                            let lines: Vec<&str> = clean_text.lines().collect();
                            // Find where our previous output ended and continue from there
                            if let Some(last_stdout_line) = stdout.lines().last() {
                                if let Some(pos) = lines
                                    .iter()
                                    .position(|&line| line.trim() == last_stdout_line.trim())
                                {
                                    if pos + 1 < lines.len() {
                                        let new_lines = &lines[pos + 1..];
                                        stdout.push('\n');
                                        stdout.push_str(&new_lines.join("\n"));
                                    }
                                } else {
                                    // Fallback: just use the clean text
                                    stdout = clean_text.to_string();
                                }
                            } else {
                                stdout = clean_text.to_string();
                            }
                        }

                        // Check if we've reached the shell prompt (command completed)
                        // Be more flexible with prompt detection
                        let has_prompt = clean_text.ends_with(&shell_prompt)
                            || clean_text.contains(&shell_prompt)
                            || clean_text.ends_with("$ ")
                            || clean_text.ends_with("# ")
                            || clean_text.contains("$ ")
                            || clean_text.contains("# ");

                        if has_prompt {
                            debug!("Shell prompt detected, command completed");
                            // Remove any prompt from the output
                            for prompt_pattern in ["$ ", "# ", &shell_prompt] {
                                if let Some(pos) = stdout.rfind(prompt_pattern) {
                                    stdout.truncate(pos);
                                    break;
                                }
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
