/*
 * Security Compliance CLI - Target System Interface
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::{
    communication::{ChannelConfig, CommunicationChannel},
    config::CommunicationConfig,
    error::{Error, Result},
    ssh_channel::SshChannel,
};
#[cfg(not(target_os = "windows"))]
use crate::serial_channel::SerialChannel;
use std::time::Duration;
use tracing::{debug, info};

pub struct Target {
    channel: Box<dyn CommunicationChannel>,
    config: CommunicationConfig,
}

impl Target {
    pub fn new(config: CommunicationConfig) -> Result<Self> {
        let channel_config = config.to_channel_config()?;
        let channel: Box<dyn CommunicationChannel> = match channel_config {
            ChannelConfig::Ssh { .. } => {
                Box::new(SshChannel::from_channel_config(ChannelConfig::Ssh {
                    host: config.host.clone().unwrap_or_default(),
                    port: config.port.unwrap_or(22),
                    user: config.user.clone().unwrap_or_default(),
                    password: config.password.clone().unwrap_or_default(),
                    ssh_key_path: config.ssh_key_path.clone(),
                    timeout: config.timeout as u32,
                    ssh_multiplex: config.ssh_multiplex.unwrap_or(false),
                })?)
            }
            #[cfg(not(target_os = "windows"))]
            ChannelConfig::Serial { .. } => {
                Box::new(SerialChannel::from_channel_config(ChannelConfig::Serial {
                    device: config.serial_device.clone().unwrap_or_default(),
                    baud_rate: config.baud_rate.unwrap_or(115200),
                    timeout: config.timeout as u32,
                    login_prompt: config.serial_login_prompt.clone(),
                    password_prompt: config.serial_password_prompt.clone(),
                    shell_prompt: config.serial_shell_prompt.clone(),
                    username: config.serial_username.clone(),
                    password: config.serial_password.clone(),
                })?)
            }
            #[cfg(target_os = "windows")]
            ChannelConfig::Serial { .. } => {
                return Err(Error::Unsupported(
                    "Serial communication is not supported on Windows due to thread safety limitations. Please use SSH instead.".to_string()
                ));
            }
        };

        Ok(Self { channel, config })
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!("Connecting to target using {}", self.channel.description());
        self.channel.connect().await
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        info!("Disconnecting from target");
        self.channel.disconnect().await
    }

    pub fn get_password(&self) -> &str {
        match self.config.channel_type.as_str() {
            "ssh" => self.config.password.as_deref().unwrap_or(""),
            "serial" => self.config.serial_password.as_deref().unwrap_or(""),
            _ => "",
        }
    }

    pub async fn execute_command(&mut self, command: &str) -> Result<CommandResult> {
        debug!("Executing command: {}", command);
        let output = self.channel.execute_command(command).await?;
        Ok(CommandResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
    }

    pub async fn execute_command_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<CommandResult> {
        debug!("Executing command with timeout {:?}: {}", timeout, command);
        let output = self
            .channel
            .execute_command_with_timeout(command, timeout)
            .await?;
        Ok(CommandResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
        })
    }

    pub async fn upload_file(&mut self, local_path: &str, remote_path: &str) -> Result<()> {
        info!("Uploading file: {} -> {}", local_path, remote_path);
        self.channel.upload_file(local_path, remote_path).await
    }

    pub async fn download_file(&mut self, remote_path: &str, local_path: &str) -> Result<()> {
        info!("Downloading file: {} -> {}", remote_path, local_path);
        self.channel.download_file(remote_path, local_path).await
    }

    pub async fn is_connected(&self) -> bool {
        self.channel.is_connected().await
    }

    pub fn get_communication_channel(&mut self) -> &mut dyn CommunicationChannel {
        self.channel.as_mut()
    }

    // Legacy compatibility methods for existing tests
    pub async fn get_kernel_version(&mut self) -> Result<String> {
        let result = self.execute_command("uname -r").await?;
        if result.exit_code == 0 {
            Ok(result.stdout.trim().to_string())
        } else {
            Err(Error::CommandExecution(format!(
                "Failed to get kernel version: {}",
                result.stderr
            )))
        }
    }

    pub async fn get_uptime(&mut self) -> Result<String> {
        let result = self.execute_command("uptime -p").await?;
        if result.exit_code == 0 {
            Ok(result.stdout.trim().to_string())
        } else {
            // Fallback to basic uptime
            let result = self.execute_command("uptime").await?;
            if result.exit_code == 0 {
                Ok(result.stdout.trim().to_string())
            } else {
                Err(Error::CommandExecution(format!(
                    "Failed to get uptime: {}",
                    result.stderr
                )))
            }
        }
    }

    pub async fn get_cpu_info(&mut self) -> Result<String> {
        let result = self
            .execute_command("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2")
            .await?;
        if result.exit_code == 0 {
            Ok(result.stdout.trim().to_string())
        } else {
            Ok("Unknown CPU".to_string())
        }
    }

    pub async fn get_memory_usage(&mut self) -> Result<String> {
        let result = self
            .execute_command("free -h | grep Mem | awk '{print $3 \"/\" $2}'")
            .await?;
        if result.exit_code == 0 {
            Ok(result.stdout.trim().to_string())
        } else {
            Ok("Unknown memory usage".to_string())
        }
    }

    pub async fn get_disk_usage(&mut self) -> Result<String> {
        let result = self
            .execute_command("df -h / | tail -1 | awk '{print $3 \"/\" $2 \" (\" $5 \" used)\"}'")
            .await?;
        if result.exit_code == 0 {
            Ok(result.stdout.trim().to_string())
        } else {
            Ok("Unknown disk usage".to_string())
        }
    }

    pub async fn get_power_governor(&mut self) -> Result<String> {
        let result = self.execute_command("cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'N/A'").await?;
        Ok(result.stdout.trim().to_string())
    }

    pub async fn get_os_release(&mut self) -> Result<String> {
        let result = self.execute_command("cat /etc/os-release").await?;
        if result.exit_code == 0 {
            Ok(result.stdout)
        } else {
            Ok("Unknown OS".to_string())
        }
    }

    pub async fn get_foundries_registration(&mut self) -> Result<String> {
        let result = self.execute_command("fioctl devices list --factory $(cat /etc/hostname) 2>/dev/null | grep $(cat /etc/hostname) | awk '{print $2}' || echo 'Not registered'").await?;
        Ok(result.stdout.trim().to_string())
    }

    pub async fn get_wireguard_status(&mut self) -> Result<String> {
        let result = self
            .execute_command("systemctl is-active wireguard-client 2>/dev/null || echo 'Inactive'")
            .await?;
        Ok(result.stdout.trim().to_string())
    }

    pub async fn file_exists(&mut self, path: &str) -> Result<bool> {
        let result = self.execute_command(&format!("test -f {}", path)).await?;
        Ok(result.exit_code == 0)
    }

    pub async fn directory_exists(&mut self, path: &str) -> Result<bool> {
        let result = self.execute_command(&format!("test -d {}", path)).await?;
        Ok(result.exit_code == 0)
    }

    pub async fn read_file(&mut self, path: &str) -> Result<String> {
        let result = self.execute_command(&format!("cat {}", path)).await?;
        if result.exit_code == 0 {
            Ok(result.stdout)
        } else {
            Err(Error::CommandExecution(format!(
                "Failed to read file {}: {}",
                path, result.stderr
            )))
        }
    }

    pub async fn write_file(&mut self, path: &str, content: &str) -> Result<()> {
        let escaped_content = content.replace('\'', "'\"'\"'");
        let result = self
            .execute_command(&format!("echo '{}' > {}", escaped_content, path))
            .await?;

        if result.exit_code == 0 {
            Ok(())
        } else {
            Err(Error::CommandExecution(format!(
                "Failed to write file {}: {}",
                path, result.stderr
            )))
        }
    }

    pub async fn get_process_count(&mut self) -> Result<usize> {
        let result = self.execute_command("ps aux | wc -l").await?;
        if result.exit_code == 0 {
            let count = result.stdout.trim().parse::<usize>().unwrap_or(0);
            // Subtract 1 for the header line
            Ok(count.saturating_sub(1))
        } else {
            Ok(0)
        }
    }

    pub async fn get_network_interfaces(&mut self) -> Result<Vec<String>> {
        let result = self
            .execute_command("ip link show | grep '^[0-9]' | awk -F': ' '{print $2}' | grep -v lo")
            .await?;
        if result.exit_code == 0 {
            Ok(result
                .stdout
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect())
        } else {
            Ok(vec![])
        }
    }

    pub async fn get_listening_ports(&mut self) -> Result<Vec<u16>> {
        let result = self
            .execute_command("ss -tlnp | grep LISTEN | awk '{print $4}' | cut -d':' -f2 | sort -n")
            .await?;
        if result.exit_code == 0 {
            Ok(result
                .stdout
                .lines()
                .filter_map(|line| line.trim().parse::<u16>().ok())
                .collect())
        } else {
            Ok(vec![])
        }
    }

    pub async fn service_is_active(&mut self, service: &str) -> Result<bool> {
        let result = self
            .execute_command(&format!("systemctl is-active {}", service))
            .await?;
        Ok(result.exit_code == 0 && result.stdout.trim() == "active")
    }

    pub async fn service_is_enabled(&mut self, service: &str) -> Result<bool> {
        let result = self
            .execute_command(&format!("systemctl is-enabled {}", service))
            .await?;
        Ok(result.exit_code == 0 && result.stdout.trim() == "enabled")
    }

    pub async fn get_boot_time(&mut self) -> Result<Duration> {
        let result = self
            .execute_command(
                "systemd-analyze | grep 'Startup finished' | awk '{print $(NF-1)}' | sed 's/s//'",
            )
            .await?;
        if result.exit_code == 0 {
            let seconds: f64 = result.stdout.trim().parse().unwrap_or(0.0);
            Ok(Duration::from_secs_f64(seconds))
        } else {
            Ok(Duration::from_secs(0))
        }
    }

    pub async fn get_cpu_usage(&mut self) -> Result<f64> {
        let result = self
            .execute_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | sed 's/%us,//'")
            .await?;
        if result.exit_code == 0 {
            Ok(result.stdout.trim().parse().unwrap_or(0.0))
        } else {
            Ok(0.0)
        }
    }

    pub async fn get_memory_usage_mb(&mut self) -> Result<u64> {
        let result = self
            .execute_command("free -m | grep Mem | awk '{print $3}'")
            .await?;
        if result.exit_code == 0 {
            Ok(result.stdout.trim().parse().unwrap_or(0))
        } else {
            Ok(0)
        }
    }

    pub async fn get_system_info(&mut self) -> Result<SystemInfo> {
        Ok(SystemInfo {
            kernel_version: self
                .get_kernel_version()
                .await
                .unwrap_or_else(|_| "Unknown".to_string()),
            uptime: self
                .get_uptime()
                .await
                .unwrap_or_else(|_| "Unknown".to_string()),
            cpu_info: self
                .get_cpu_info()
                .await
                .unwrap_or_else(|_| "Unknown".to_string()),
            memory_usage: self
                .get_memory_usage()
                .await
                .unwrap_or_else(|_| "Unknown".to_string()),
            disk_usage: self
                .get_disk_usage()
                .await
                .unwrap_or_else(|_| "Unknown".to_string()),
            power_governor: self
                .get_power_governor()
                .await
                .unwrap_or_else(|_| "Unknown".to_string()),
            os_release: self
                .get_os_release()
                .await
                .unwrap_or_else(|_| "Unknown".to_string()),
            foundries_registration: self
                .get_foundries_registration()
                .await
                .unwrap_or_else(|_| "Unknown".to_string()),
            wireguard_status: self
                .get_wireguard_status()
                .await
                .unwrap_or_else(|_| "Unknown".to_string()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl CommandResult {
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemInfo {
    pub kernel_version: String,
    pub uptime: String,
    pub cpu_info: String,
    pub memory_usage: String,
    pub disk_usage: String,
    pub power_governor: String,
    pub os_release: String,
    pub foundries_registration: String,
    pub wireguard_status: String,
}
