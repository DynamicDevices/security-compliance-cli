/*
 * Security Compliance CLI - Windows Serial Channel Implementation
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::{
    communication::{ChannelConfig, CommandOutput, CommunicationChannel},
    error::{Error, Result},
};
use async_trait::async_trait;
use bytes::BytesMut;
use serialport::SerialPort;
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Windows-compatible serial channel implementation using serialport crate
pub struct WindowsSerialChannel {
    port: Option<Arc<Mutex<Box<dyn SerialPort>>>>,
    config: ChannelConfig,
    connected: bool,
}

impl WindowsSerialChannel {
    pub fn from_channel_config(config: ChannelConfig) -> Result<Self> {
        match config {
            ChannelConfig::Serial { .. } => Ok(Self {
                port: None,
                config,
                connected: false,
            }),
            _ => Err(Error::Config(
                "WindowsSerialChannel requires Serial configuration".to_string(),
            )),
        }
    }

    fn get_config(
        &self,
    ) -> Result<(
        &str,
        u32,
        u32,
        &Option<String>,
        &Option<String>,
        &Option<String>,
        &Option<String>,
        &Option<String>,
    )> {
        match &self.config {
            ChannelConfig::Serial {
                device,
                baud_rate,
                timeout,
                login_prompt,
                password_prompt,
                shell_prompt,
                username,
                password,
            } => Ok((
                device,
                *baud_rate,
                *timeout,
                login_prompt,
                password_prompt,
                shell_prompt,
                username,
                password,
            )),
            _ => Err(Error::Config(
                "Invalid configuration for serial channel".to_string(),
            )),
        }
    }

    fn send_command(&mut self, command: &str) -> Result<()> {
        if let Some(port) = &self.port {
            let mut port_guard = port.lock().map_err(|e| {
                Error::SerialConnection(format!("Failed to lock serial port: {}", e))
            })?;

            let command_with_newline = format!("{}\r\n", command);
            port_guard
                .write_all(command_with_newline.as_bytes())
                .map_err(|e| {
                    Error::SerialConnection(format!("Failed to write to serial port: {}", e))
                })?;

            port_guard.flush().map_err(|e| {
                Error::SerialConnection(format!("Failed to flush serial port: {}", e))
            })?;

            debug!("Sent command: {}", command);
            Ok(())
        } else {
            Err(Error::SerialConnection(
                "Serial port not connected".to_string(),
            ))
        }
    }

    fn read_response(&mut self, timeout: Duration) -> Result<String> {
        if let Some(port) = &self.port {
            let mut port_guard = port.lock().map_err(|e| {
                Error::SerialConnection(format!("Failed to lock serial port: {}", e))
            })?;

            let mut buffer = BytesMut::with_capacity(4096);
            let start_time = Instant::now();

            while start_time.elapsed() < timeout {
                let mut temp_buffer = [0u8; 1024];
                match port_guard.read(&mut temp_buffer) {
                    Ok(bytes_read) if bytes_read > 0 => {
                        buffer.extend_from_slice(&temp_buffer[..bytes_read]);

                        // Convert to string and check for prompt
                        let response = String::from_utf8_lossy(&buffer);
                        let cleaned_response = self.strip_ansi_codes(&response);

                        // Look for shell prompt patterns
                        if self.has_prompt(&cleaned_response) {
                            debug!("Received response with prompt: {}", cleaned_response.trim());
                            return Ok(cleaned_response);
                        }
                    }
                    Ok(_) => {
                        // No data available, continue waiting
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                        // Timeout on read is expected, continue
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => {
                        return Err(Error::SerialConnection(format!("Read error: {}", e)));
                    }
                }
            }

            // Timeout reached
            let response = String::from_utf8_lossy(&buffer);
            let cleaned_response = self.strip_ansi_codes(&response);

            if cleaned_response.trim().is_empty() {
                Err(Error::SerialConnection(
                    "Timeout: no response received".to_string(),
                ))
            } else {
                warn!("Timeout reached, returning partial response");
                Ok(cleaned_response)
            }
        } else {
            Err(Error::SerialConnection(
                "Serial port not connected".to_string(),
            ))
        }
    }

    fn wait_for_prompt(&mut self, expected_prompt: &str, timeout: Duration) -> Result<()> {
        debug!("Waiting for prompt: {}", expected_prompt);
        let start_time = Instant::now();

        while start_time.elapsed() < timeout {
            let response = self.read_response(Duration::from_secs(1))?;
            let cleaned_response = self.strip_ansi_codes(&response);

            if cleaned_response.contains(expected_prompt) {
                debug!("Found expected prompt: {}", expected_prompt);
                return Ok(());
            }

            debug!(
                "Still waiting for prompt '{}', got: {}",
                expected_prompt,
                cleaned_response.trim()
            );
        }

        Err(Error::SerialConnection(format!(
            "Timeout waiting for prompt: {}",
            expected_prompt
        )))
    }

    async fn login_if_needed(&mut self) -> Result<()> {
        let (_, _, timeout, login_prompt, password_prompt, shell_prompt, username, password) =
            self.get_config()?;

        let timeout_duration = Duration::from_secs(timeout as u64);

        // Send some wake-up sequences
        debug!("Sending wake-up sequences");
        if let Some(port) = &self.port {
            let mut port_guard = port.lock().map_err(|e| {
                Error::SerialConnection(format!("Failed to lock serial port: {}", e))
            })?;

            // Send Ctrl-C to break out of any running process
            port_guard
                .write_all(&[0x03])
                .map_err(|e| Error::SerialConnection(format!("Failed to send Ctrl-C: {}", e)))?;

            // Send multiple line endings to wake up the device
            let line_endings: &[&[u8]] = &[b"\r\n", b"\n", b"\r"];
            for line_ending in line_endings {
                port_guard.write_all(line_ending).map_err(|e| {
                    Error::SerialConnection(format!("Failed to send line ending: {}", e))
                })?;
            }

            port_guard.flush().map_err(|e| {
                Error::SerialConnection(format!("Failed to flush serial port: {}", e))
            })?;
        }

        // Give the device time to respond
        sleep(Duration::from_millis(1000)).await;

        // Try to read any immediate response
        if let Ok(response) = self.read_response(Duration::from_secs(2)) {
            let cleaned_response = self.strip_ansi_codes(&response);
            debug!("Initial response: {}", cleaned_response.trim());

            // Check if we already have a shell prompt
            if self.has_prompt(&cleaned_response) {
                debug!("Already at shell prompt, no login needed");
                return Ok(());
            }
        }

        // Handle login if prompts are configured
        if let (Some(login_prompt), Some(username)) = (login_prompt, username) {
            debug!("Attempting login sequence");

            // Wait for login prompt
            self.wait_for_prompt(login_prompt, timeout_duration)?;

            // Send username
            self.send_command(username)?;

            // Handle password if configured
            if let (Some(password_prompt), Some(password)) = (password_prompt, password) {
                self.wait_for_prompt(password_prompt, timeout_duration)?;
                self.send_command(password)?;
            }

            // Wait for shell prompt
            if let Some(shell_prompt) = shell_prompt {
                self.wait_for_prompt(shell_prompt, timeout_duration)?;
            } else {
                // Wait for common shell prompts
                let response = self.read_response(timeout_duration)?;
                if !self.has_prompt(&response) {
                    return Err(Error::SerialConnection(
                        "Failed to reach shell prompt after login".to_string(),
                    ));
                }
            }
        }

        debug!("Login sequence completed successfully");
        Ok(())
    }

    fn strip_ansi_codes(&self, input: &str) -> String {
        // Remove ANSI escape sequences
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars();

        while let Some(ch) = chars.next() {
            if ch == '\x1b' {
                // Skip ANSI escape sequence
                if let Some('[') = chars.next() {
                    // Skip until we find a letter (end of ANSI sequence)
                    for next_ch in chars.by_ref() {
                        if next_ch.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            } else if ch != '\r' {
                // Keep everything except carriage returns
                result.push(ch);
            }
        }

        result
    }

    fn has_prompt(&self, text: &str) -> bool {
        // Look for common shell prompt patterns
        let lines: Vec<&str> = text.lines().collect();
        if let Some(last_line) = lines.last() {
            let trimmed = last_line.trim();
            // Check for common prompt endings
            trimmed.ends_with("$ ")
                || trimmed.ends_with("# ")
                || trimmed.ends_with("$")
                || trimmed.ends_with("#")
                || trimmed.contains("$ ")
                || trimmed.contains("# ")
        } else {
            false
        }
    }
}

#[async_trait]
impl CommunicationChannel for WindowsSerialChannel {
    async fn connect(&mut self) -> Result<()> {
        let (device, baud_rate, timeout, _, _, _, _, _) = self.get_config()?;

        info!(
            "Connecting to serial device: {} at {} baud",
            device, baud_rate
        );

        let port = serialport::new(device, baud_rate)
            .timeout(Duration::from_millis(timeout as u64))
            .data_bits(serialport::DataBits::Eight)
            .parity(serialport::Parity::None)
            .stop_bits(serialport::StopBits::One)
            .flow_control(serialport::FlowControl::None)
            .open()
            .map_err(|e| Error::SerialConnection(format!("Failed to open serial port: {}", e)))?;

        self.port = Some(Arc::new(Mutex::new(port)));
        self.connected = true;

        // Attempt login
        self.login_if_needed().await?;

        info!("Successfully connected to serial device");
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<()> {
        if self.connected {
            self.port = None;
            self.connected = false;
            info!("Disconnected from serial device");
        }
        Ok(())
    }

    async fn execute_command(&mut self, command: &str) -> Result<CommandOutput> {
        self.execute_command_with_timeout(command, Duration::from_secs(30))
            .await
    }

    async fn execute_command_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<CommandOutput> {
        if !self.connected {
            return Err(Error::SerialConnection(
                "Not connected to serial device".to_string(),
            ));
        }

        debug!("Executing command: {}", command);

        // Send the command
        self.send_command(command)?;

        // Read the response
        let response = self.read_response(timeout)?;
        let cleaned_response = self.strip_ansi_codes(&response);

        // Parse the output to separate command echo from actual output
        let lines: Vec<&str> = cleaned_response.lines().collect();
        let mut stdout_lines = Vec::new();
        let mut found_command = false;

        for line in lines {
            let trimmed_line = line.trim();

            // Skip empty lines at the start
            if !found_command && trimmed_line.is_empty() {
                continue;
            }

            // Look for the command echo (may be preceded by a prompt)
            if !found_command && (trimmed_line.contains(command) || trimmed_line.ends_with(command))
            {
                found_command = true;
                continue;
            }

            // Skip the command line itself
            if found_command {
                // Check if this line is a shell prompt (end of output)
                if self.has_prompt(line) {
                    break;
                }
                stdout_lines.push(line);
            }
        }

        // Join the output lines and clean up
        let mut stdout = stdout_lines.join("\n");

        // Remove any trailing prompts
        if let Some(last_newline) = stdout.rfind('\n') {
            let (content, maybe_prompt) = stdout.split_at(last_newline);
            if self.has_prompt(maybe_prompt) {
                stdout = content.to_string();
            }
        }

        let stdout = stdout.trim().to_string();

        debug!("Command output: {}", stdout);

        Ok(CommandOutput {
            stdout,
            stderr: String::new(),
            exit_code: 0,
        })
    }

    async fn is_connected(&self) -> bool {
        self.connected
    }

    fn description(&self) -> String {
        match &self.config {
            ChannelConfig::Serial {
                device, baud_rate, ..
            } => {
                format!("Windows Serial: {} @ {} baud", device, baud_rate)
            }
            _ => "Windows Serial Channel".to_string(),
        }
    }

    async fn upload_file(&mut self, _local_path: &str, _remote_path: &str) -> Result<()> {
        Err(Error::Unsupported(
            "File upload not supported via serial communication".to_string(),
        ))
    }

    async fn download_file(&mut self, _remote_path: &str, _local_path: &str) -> Result<()> {
        Err(Error::Unsupported(
            "File download not supported via serial communication".to_string(),
        ))
    }
}
