/*
 * Security Compliance CLI - Target System Interface
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::{
    config::TargetConfig,
    error::{Error, Result},
    ssh::SshClient,
};
use std::time::Duration;
use tracing::{debug, info};

pub struct Target {
    ssh_client: SshClient,
    config: TargetConfig,
}

impl Target {
    pub fn new(config: TargetConfig) -> Result<Self> {
        let ssh_client = SshClient::new(&config)?;

        Ok(Self { ssh_client, config })
    }

    pub async fn connect(&mut self) -> Result<()> {
        info!(
            "Connecting to target {}:{}",
            self.config.host, self.config.port
        );
        self.ssh_client.connect().await
    }

    pub fn get_password(&self) -> &str {
        &self.config.password
    }

    pub async fn execute_command(&mut self, command: &str) -> Result<CommandResult> {
        debug!("Executing command: {}", command);
        self.ssh_client.execute_command(command).await
    }

    pub async fn execute_command_with_timeout(
        &mut self,
        command: &str,
        timeout: Duration,
    ) -> Result<CommandResult> {
        debug!("Executing command with timeout {:?}: {}", timeout, command);
        self.ssh_client
            .execute_command_with_timeout(command, timeout)
            .await
    }

    pub async fn file_exists(&mut self, path: &str) -> Result<bool> {
        let result = self
            .execute_command(&format!(
                "test -f {} && echo 'exists' || echo 'not_found'",
                path
            ))
            .await?;
        Ok(result.stdout.trim() == "exists")
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

    pub async fn get_system_info(&mut self) -> Result<SystemInfo> {
        let uname = self.execute_command("uname -a").await?;
        let uptime = self.execute_command("uptime").await?;
        let memory = self.execute_command("free -m").await?;
        let kernel_version = self.execute_command("uname -r").await?;
        let os_release = self.read_file("/etc/os-release").await.unwrap_or_default();

        // Check Foundries.io registration status
        let foundries_registration = self.check_foundries_registration().await;

        // Check WireGuard VPN status
        let wireguard_status = self.check_wireguard_status().await;

        // Get disk usage information
        let disk_usage = self.get_disk_usage().await;

        // Get CPU information
        let cpu_info = self.get_cpu_info().await;

        // Get detailed memory usage
        let memory_usage = self.get_memory_usage().await;

        // Get power governor configuration
        let power_governor = self.get_power_governor().await;

        Ok(SystemInfo {
            uname: uname.stdout.trim().to_string(),
            uptime: uptime.stdout.trim().to_string(),
            memory_info: memory.stdout.trim().to_string(),
            kernel_version: kernel_version.stdout.trim().to_string(),
            os_release,
            foundries_registration,
            wireguard_status,
            disk_usage,
            cpu_info,
            memory_usage,
            power_governor,
        })
    }

    async fn check_foundries_registration(&mut self) -> String {
        // Check if device is registered with Foundries portal
        // Look for device credentials and registration status

        // Check for device gateway credentials
        let device_creds = self
            .execute_command("ls -la /var/sota/device-creds* 2>/dev/null | wc -l")
            .await
            .unwrap_or_default();
        let has_device_creds = device_creds.stdout.trim().parse::<i32>().unwrap_or(0) > 0;

        // Check for device UUID/ID
        let device_uuid = self
            .execute_command("cat /var/sota/device-uuid 2>/dev/null || echo 'not_found'")
            .await
            .unwrap_or_default();
        let has_device_uuid =
            !device_uuid.stdout.contains("not_found") && !device_uuid.stdout.trim().is_empty();

        // Check for aktualizr-lite service (OTA client)
        let aktualizr_status = self
            .execute_command("systemctl is-active aktualizr-lite 2>/dev/null || echo 'inactive'")
            .await
            .unwrap_or_default();
        let aktualizr_active = aktualizr_status.stdout.trim() == "active";

        // Check for device registration in aktualizr config
        let aktualizr_config = self
            .execute_command(
                "cat /var/sota/sota.toml 2>/dev/null | grep -E 'device_id|server' | head -2",
            )
            .await
            .unwrap_or_default();
        let has_server_config = aktualizr_config.stdout.contains("server")
            || aktualizr_config.stdout.contains("device_id");

        // Check for recent communication with Foundries
        let last_update_check = self.execute_command("journalctl -u aktualizr-lite --since='24 hours ago' | grep -i 'check.*update\\|target.*update' | tail -1").await.unwrap_or_default();
        let recent_communication = !last_update_check.stdout.trim().is_empty();

        // Determine registration status
        if has_device_creds && has_device_uuid && aktualizr_active && has_server_config {
            if recent_communication {
                "Registered and Active".to_string()
            } else {
                "Registered but No Recent Communication".to_string()
            }
        } else if has_device_creds || has_device_uuid {
            "Partially Registered".to_string()
        } else {
            "Not Registered".to_string()
        }
    }

    async fn check_wireguard_status(&mut self) -> String {
        // Check WireGuard VPN status
        let mut status_parts = Vec::<String>::new();

        // Check if WireGuard kernel module is loaded
        let wg_module = self
            .execute_command("lsmod | grep wireguard")
            .await
            .unwrap_or_default();
        let module_loaded = !wg_module.stdout.trim().is_empty();

        // Check for WireGuard interfaces
        let wg_interfaces = self
            .execute_command(
                "ip link show type wireguard 2>/dev/null | grep -o 'wg[0-9]*' | head -5",
            )
            .await
            .unwrap_or_default();
        let interfaces: Vec<&str> = wg_interfaces
            .stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();

        // Check WireGuard service status
        let wg_service = self
            .execute_command(
                "systemctl is-active wg-quick@* 2>/dev/null | grep -v 'inactive' | head -1",
            )
            .await
            .unwrap_or_default();
        let service_active = wg_service.stdout.trim() == "active";

        // Check for WireGuard configuration files
        let wg_configs = self
            .execute_command("ls /etc/wireguard/*.conf 2>/dev/null | wc -l")
            .await
            .unwrap_or_default();
        let config_count = wg_configs.stdout.trim().parse::<i32>().unwrap_or(0);

        // Check active connections
        let wg_show = self
            .execute_command("wg show 2>/dev/null | grep -E 'interface|peer' | wc -l")
            .await
            .unwrap_or_default();
        let active_connections = wg_show.stdout.trim().parse::<i32>().unwrap_or(0);

        // Build status string
        if !module_loaded {
            return "Not Available (module not loaded)".to_string();
        }

        status_parts.push("Module Loaded".to_string());

        if !interfaces.is_empty() {
            status_parts.push(format!("Interfaces: {}", interfaces.join(", ")));
        }

        if service_active {
            status_parts.push("Service Active".to_string());
        }

        if config_count > 0 {
            status_parts.push(format!("{} Config(s)", config_count));
        }

        if active_connections > 0 {
            status_parts.push(format!("{} Active Connection(s)", active_connections / 2));
            // Divide by 2 as each connection shows interface + peer
        }

        if status_parts.len() > 1 {
            format!("Enabled ({})", status_parts.join(", "))
        } else if status_parts.len() == 1 {
            "Available but Not Configured".to_string()
        } else {
            "Disabled".to_string()
        }
    }

    async fn get_disk_usage(&mut self) -> String {
        // Get filesystem usage information - prioritize root filesystem
        let df_output = self
            .execute_command("df -h | grep -E '^/dev|^overlay|^tmpfs' | head -10")
            .await
            .unwrap_or_default();

        if df_output.stdout.trim().is_empty() {
            return "Unable to determine disk usage".to_string();
        }

        // Parse df output to get filesystem usage, prioritizing root
        let mut disk_info = Vec::new();
        let mut root_found = false;

        for line in df_output.stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let _filesystem = parts[0];
                let size = parts[1];
                let used = parts[2];
                let _available = parts[3];
                let use_percent = parts[4];
                let mount_point = parts[5];

                // Prioritize root filesystem
                if mount_point == "/" {
                    disk_info.insert(
                        0,
                        format!("Root: {} total, {} used ({})", size, used, use_percent),
                    );
                    root_found = true;
                } else if mount_point == "/var" || mount_point == "/boot" {
                    disk_info.push(format!(
                        "{}: {} total, {} used ({})",
                        mount_point, size, used, use_percent
                    ));
                }
            }
        }

        // If no root filesystem found, try a direct query
        if !root_found {
            let root_df = self
                .execute_command("df -h / 2>/dev/null | tail -1")
                .await
                .unwrap_or_default();
            if !root_df.stdout.trim().is_empty() {
                let parts: Vec<&str> = root_df.stdout.split_whitespace().collect();
                if parts.len() >= 5 {
                    disk_info.insert(
                        0,
                        format!("Root: {} total, {} used ({})", parts[1], parts[2], parts[4]),
                    );
                }
            }
        }

        if disk_info.is_empty() {
            "Unable to parse disk usage".to_string()
        } else {
            // Return only the most important info (root + one other if available)
            if disk_info.len() > 2 {
                format!("{}, {}", disk_info[0], disk_info[1])
            } else {
                disk_info.join(", ")
            }
        }
    }

    async fn get_cpu_info(&mut self) -> String {
        // Get CPU count and basic information
        let cpu_count = self.execute_command("nproc").await.unwrap_or_default();
        let cpu_model = self
            .execute_command(
                "cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2 | xargs",
            )
            .await
            .unwrap_or_default();
        let cpu_arch = self.execute_command("uname -m").await.unwrap_or_default();

        // Get CPU frequencies
        let cpu_freq_current = self
            .execute_command("cat /proc/cpuinfo | grep 'cpu MHz' | head -1 | cut -d':' -f2 | xargs")
            .await
            .unwrap_or_default();
        let cpu_freq_max = self
            .execute_command(
                "cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null | head -1",
            )
            .await
            .unwrap_or_default();
        let cpu_freq_min = self
            .execute_command(
                "cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq 2>/dev/null | head -1",
            )
            .await
            .unwrap_or_default();

        let mut cpu_info_parts = Vec::new();

        // CPU count
        if !cpu_count.stdout.trim().is_empty() {
            cpu_info_parts.push(format!("{} cores", cpu_count.stdout.trim()));
        }

        // Architecture
        if !cpu_arch.stdout.trim().is_empty() {
            cpu_info_parts.push(cpu_arch.stdout.trim().to_string());
        }

        // CPU model (simplified)
        if !cpu_model.stdout.trim().is_empty() {
            let model = cpu_model.stdout.trim();
            // Simplify long model names
            if model.len() > 50 {
                cpu_info_parts.push(format!("{}...", &model[..47]));
            } else {
                cpu_info_parts.push(model.to_string());
            }
        }

        // Current frequency
        if !cpu_freq_current.stdout.trim().is_empty() {
            if let Ok(freq_mhz) = cpu_freq_current.stdout.trim().parse::<f64>() {
                if freq_mhz > 1000.0 {
                    cpu_info_parts.push(format!("{:.1} GHz", freq_mhz / 1000.0));
                } else {
                    cpu_info_parts.push(format!("{:.0} MHz", freq_mhz));
                }
            }
        }

        // Frequency range (if available)
        if !cpu_freq_max.stdout.trim().is_empty() && !cpu_freq_min.stdout.trim().is_empty() {
            if let (Ok(max_khz), Ok(min_khz)) = (
                cpu_freq_max.stdout.trim().parse::<u64>(),
                cpu_freq_min.stdout.trim().parse::<u64>(),
            ) {
                let max_ghz = max_khz as f64 / 1_000_000.0;
                let min_ghz = min_khz as f64 / 1_000_000.0;
                cpu_info_parts.push(format!("({:.1}-{:.1} GHz range)", min_ghz, max_ghz));
            }
        }

        if cpu_info_parts.is_empty() {
            "Unable to determine CPU information".to_string()
        } else {
            cpu_info_parts.join(", ")
        }
    }

    async fn get_memory_usage(&mut self) -> String {
        // Get detailed memory information
        let meminfo = self
            .execute_command(
                "cat /proc/meminfo | grep -E '^MemTotal|^MemFree|^MemAvailable|^Buffers|^Cached'",
            )
            .await
            .unwrap_or_default();

        if meminfo.stdout.trim().is_empty() {
            return "Unable to determine memory usage".to_string();
        }

        let mut mem_total_kb = 0u64;
        let mut mem_available_kb = 0u64;
        let mut mem_free_kb = 0u64;

        for line in meminfo.stdout.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let value = value.trim().replace(" kB", "");
                if let Ok(kb) = value.parse::<u64>() {
                    match key.trim() {
                        "MemTotal" => mem_total_kb = kb,
                        "MemAvailable" => mem_available_kb = kb,
                        "MemFree" => mem_free_kb = kb,
                        _ => {}
                    }
                }
            }
        }

        if mem_total_kb == 0 {
            return "Unable to parse memory information".to_string();
        }

        // Use MemAvailable if available, otherwise use MemFree
        let available_kb = if mem_available_kb > 0 {
            mem_available_kb
        } else {
            mem_free_kb
        };
        let used_kb = mem_total_kb - available_kb;
        let usage_percent = (used_kb as f64 / mem_total_kb as f64) * 100.0;

        // Convert to human readable units
        let total_mb = mem_total_kb / 1024;
        let used_mb = used_kb / 1024;
        let _available_mb = available_kb / 1024;

        if total_mb > 1024 {
            let total_gb = total_mb as f64 / 1024.0;
            let used_gb = used_mb as f64 / 1024.0;
            format!(
                "{:.1} GB total, {:.1} GB used ({:.1}%)",
                total_gb, used_gb, usage_percent
            )
        } else {
            format!(
                "{} MB total, {} MB used ({:.1}%)",
                total_mb, used_mb, usage_percent
            )
        }
    }

    async fn get_power_governor(&mut self) -> String {
        // Check CPU frequency governor
        let governor = self
            .execute_command(
                "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null",
            )
            .await
            .unwrap_or_default();

        if governor.stdout.trim().is_empty() {
            // Check if cpufreq is available at all
            let cpufreq_available = self
                .execute_command("ls /sys/devices/system/cpu/cpu0/cpufreq/ 2>/dev/null | wc -l")
                .await
                .unwrap_or_default();
            let has_cpufreq = cpufreq_available.stdout.trim().parse::<i32>().unwrap_or(0) > 0;

            if !has_cpufreq {
                // Check if this is an embedded system with fixed frequency
                let cpu_model = self
                    .execute_command("cat /proc/cpuinfo | grep -i 'model\\|processor' | head -1")
                    .await
                    .unwrap_or_default();
                if cpu_model.stdout.to_lowercase().contains("arm")
                    || cpu_model.stdout.to_lowercase().contains("cortex")
                {
                    return "Fixed frequency (embedded ARM)".to_string();
                } else {
                    return "No frequency scaling support".to_string();
                }
            } else {
                return "Frequency scaling available but governor not set".to_string();
            }
        }

        let current_governor = governor.stdout.trim();

        // Get available governors
        let available_governors = self
            .execute_command(
                "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors 2>/dev/null",
            )
            .await
            .unwrap_or_default();

        // Get current CPU frequency
        let current_freq = self
            .execute_command(
                "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null",
            )
            .await
            .unwrap_or_default();

        let mut governor_info = vec![current_governor.to_string()];

        // Add frequency info if available
        if !current_freq.stdout.trim().is_empty() {
            if let Ok(freq_khz) = current_freq.stdout.trim().parse::<u64>() {
                let freq_mhz = freq_khz / 1000;
                if freq_mhz > 1000 {
                    governor_info.push(format!("{:.1} GHz", freq_mhz as f64 / 1000.0));
                } else {
                    governor_info.push(format!("{} MHz", freq_mhz));
                }
            }
        }

        // Add available governors info (but keep it concise)
        if !available_governors.stdout.trim().is_empty() {
            let available: Vec<&str> = available_governors.stdout.split_whitespace().collect();
            if available.len() > 1 {
                // Only show if there are multiple options
                governor_info.push(format!("({} options)", available.len()));
            }
        }

        governor_info.join(", ")
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        info!("Disconnecting from target");
        self.ssh_client.disconnect().await
    }

    pub fn get_ssh_client(&mut self) -> &mut SshClient {
        &mut self.ssh_client
    }
}

#[derive(Debug, Clone, Default)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemInfo {
    pub uname: String,
    pub uptime: String,
    pub memory_info: String,
    pub kernel_version: String,
    pub os_release: String,
    pub foundries_registration: String,
    pub wireguard_status: String,
    pub disk_usage: String,
    pub cpu_info: String,
    pub memory_usage: String,
    pub power_governor: String,
}
