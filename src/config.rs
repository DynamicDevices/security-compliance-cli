use crate::cli::{Cli, MachineType, OutputFormat};
use crate::communication::ChannelConfig;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub communication: CommunicationConfig,
    pub output: OutputConfig,
    pub tests: TestConfig,
    pub thresholds: ThresholdConfig,
    pub machine: Option<MachineConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationConfig {
    pub channel_type: String, // "ssh" or "serial"
    // SSH fields
    pub host: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub password: Option<String>,
    pub ssh_key_path: Option<String>,
    pub ssh_multiplex: Option<bool>,
    // Serial fields
    pub serial_device: Option<String>,
    pub baud_rate: Option<u32>,
    pub serial_username: Option<String>,
    pub serial_password: Option<String>,
    pub serial_login_prompt: Option<String>,
    pub serial_password_prompt: Option<String>,
    pub serial_shell_prompt: Option<String>,
    // Common fields
    pub timeout: u64,
}

impl CommunicationConfig {
    pub fn to_channel_config(&self) -> Result<ChannelConfig> {
        match self.channel_type.as_str() {
            "ssh" => Ok(ChannelConfig::Ssh {
                host: self.host.clone().unwrap_or_else(|| "localhost".to_string()),
                port: self.port.unwrap_or(22),
                user: self.user.clone().unwrap_or_else(|| "root".to_string()),
                password: self.password.clone().unwrap_or_default(),
                ssh_key_path: self.ssh_key_path.clone(),
                timeout: self.timeout as u32,
                ssh_multiplex: self.ssh_multiplex.unwrap_or(false),
            }),
            "serial" => Ok(ChannelConfig::Serial {
                device: self.serial_device.clone().ok_or_else(|| {
                    anyhow::anyhow!("Serial device path is required for serial communication")
                })?,
                baud_rate: self.baud_rate.unwrap_or(115200),
                timeout: self.timeout as u32,
                login_prompt: self.serial_login_prompt.clone(),
                password_prompt: self.serial_password_prompt.clone(),
                shell_prompt: self.serial_shell_prompt.clone(),
                username: self.serial_username.clone(),
                password: self.serial_password.clone(),
            }),
            _ => Err(anyhow::anyhow!(
                "Unsupported communication channel type: {}",
                self.channel_type
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    pub format: String,
    pub file: Option<String>,
    pub verbose: u8,
    pub colors: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConfig {
    pub suite: String,
    pub mode: String,
    pub continue_on_failure: bool,
    pub parallel: bool,
    pub timeout_per_test: u64,
    pub retries: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub boot_time_max_ms: u64,
    pub memory_usage_max_mb: u64,
    pub cpu_usage_max_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineConfig {
    pub machine_type: String,
    pub auto_detect: bool,
    pub hardware_features: Vec<String>,
}

impl Config {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let mut config = if let Some(config_file) = &cli.config {
            Self::from_file(config_file)?
        } else {
            Self::default()
        };

        // Override with CLI arguments
        // Only override communication settings if explicitly provided via CLI
        let cli_has_serial = cli.serial_device.is_some();
        let cli_has_ssh = !cli.host.is_empty()
            || cli.port != 22
            || !cli.user.is_empty()
            || !cli.password.is_empty()
            || cli.identity_file.is_some();

        // Determine if we should override the communication config
        let should_override_comm = cli_has_serial || (cli.config.is_none() && cli_has_ssh);

        if should_override_comm {
            // Determine communication channel type
            let channel_type = if cli_has_serial { "serial" } else { "ssh" };

            // Configure communication based on channel type
            config.communication = CommunicationConfig {
                channel_type: channel_type.to_string(),
                // SSH fields
                host: if channel_type == "ssh" {
                    Some(cli.host.clone())
                } else {
                    None
                },
                port: if channel_type == "ssh" {
                    Some(cli.port)
                } else {
                    None
                },
                user: if channel_type == "ssh" {
                    Some(cli.user.clone())
                } else {
                    None
                },
                password: if channel_type == "ssh" {
                    Some(cli.password.clone())
                } else {
                    None
                },
                ssh_key_path: cli
                    .identity_file
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string()),
                ssh_multiplex: if channel_type == "ssh" {
                    Some(true)
                } else {
                    None
                },
                // Serial fields
                serial_device: cli.serial_device.clone(),
                baud_rate: if channel_type == "serial" {
                    Some(cli.baud_rate)
                } else {
                    None
                },
                serial_username: cli.serial_username.clone(),
                serial_password: cli.serial_password.clone(),
                serial_login_prompt: if channel_type == "serial" {
                    Some(cli.serial_login_prompt.clone())
                } else {
                    None
                },
                serial_password_prompt: if channel_type == "serial" {
                    Some(cli.serial_password_prompt.clone())
                } else {
                    None
                },
                serial_shell_prompt: if channel_type == "serial" {
                    Some(cli.serial_shell_prompt.clone())
                } else {
                    None
                },
                // Common fields
                timeout: cli.timeout,
            };
        }
        config.output.verbose = cli.verbose;
        config.output.format = match cli.format {
            OutputFormat::Human => "human".to_string(),
            OutputFormat::Json => "json".to_string(),
            OutputFormat::Junit => "junit".to_string(),
            OutputFormat::Markdown => "markdown".to_string(),
            OutputFormat::Cra => "cra".to_string(),
            OutputFormat::Red => "red".to_string(),
            OutputFormat::Pdf => "pdf".to_string(),
        };

        if let Some(output_file) = &cli.output {
            config.output.file = Some(output_file.to_string_lossy().to_string());
        }

        // Handle machine configuration
        if let Some(machine_type) = &cli.machine {
            let machine_type_str = match machine_type {
                MachineType::Imx93JaguarEink => "imx93-jaguar-eink".to_string(),
                MachineType::Imx8mmJaguarSentai => "imx8mm-jaguar-sentai".to_string(),
            };

            config.machine = Some(MachineConfig {
                machine_type: machine_type_str,
                auto_detect: false, // Explicitly set via CLI
                hardware_features: get_machine_features(machine_type),
            });
        } else {
            // Enable auto-detection by default
            config.machine = Some(MachineConfig {
                machine_type: "auto".to_string(),
                auto_detect: true,
                hardware_features: vec![], // Will be populated during detection
            });
        }

        Ok(config)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).context("Failed to read configuration file")?;

        let config: Self = toml::from_str(&content)
            .or_else(|_| serde_json::from_str(&content))
            .context("Failed to parse configuration file (expected TOML or JSON)")?;

        Ok(config)
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self).context("Failed to serialize configuration")?;

        fs::write(path, content).context("Failed to write configuration file")?;

        Ok(())
    }

    /// Update machine configuration with detected information
    pub fn update_machine_config(
        &mut self,
        machine_type: Option<MachineType>,
        features: Vec<String>,
    ) {
        if let Some(machine_config) = &mut self.machine {
            if machine_config.auto_detect {
                if let Some(detected_type) = machine_type {
                    machine_config.machine_type = match detected_type {
                        MachineType::Imx93JaguarEink => "imx93-jaguar-eink".to_string(),
                        MachineType::Imx8mmJaguarSentai => "imx8mm-jaguar-sentai".to_string(),
                    };
                } else {
                    machine_config.machine_type = "unknown".to_string();
                }
                machine_config.hardware_features = features;
            }
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            communication: CommunicationConfig {
                channel_type: "ssh".to_string(),
                host: Some("192.168.0.36".to_string()),
                port: Some(22),
                user: Some("fio".to_string()),
                password: Some("fio".to_string()),
                ssh_key_path: None,
                ssh_multiplex: Some(true),
                serial_device: None,
                baud_rate: None,
                serial_username: None,
                serial_password: None,
                serial_login_prompt: None,
                serial_password_prompt: None,
                serial_shell_prompt: None,
                timeout: 30,
            },
            output: OutputConfig {
                format: "human".to_string(),
                file: None,
                verbose: 0,
                colors: true,
            },
            tests: TestConfig {
                suite: "all".to_string(),
                mode: "pre-production".to_string(),
                continue_on_failure: false,
                parallel: false,
                timeout_per_test: 60,
                retries: 1,
            },
            thresholds: ThresholdConfig {
                boot_time_max_ms: 30000,
                memory_usage_max_mb: 512,
                cpu_usage_max_percent: 80.0,
            },
            machine: Some(MachineConfig {
                machine_type: "auto".to_string(),
                auto_detect: true,
                hardware_features: vec![],
            }),
        }
    }
}

fn get_machine_features(machine_type: &MachineType) -> Vec<String> {
    match machine_type {
        MachineType::Imx93JaguarEink => vec![
            "imx93".to_string(),
            "edgelock-enclave".to_string(),
            "caam".to_string(),
            "secure-boot".to_string(),
            "trustzone".to_string(),
            "op-tee".to_string(),
            "tf-a".to_string(),
            "eink-display".to_string(),
            "pcf2131-rtc".to_string(),
        ],
        MachineType::Imx8mmJaguarSentai => vec![
            "imx8mm".to_string(),
            "caam".to_string(),
            "secure-boot".to_string(),
            "trustzone".to_string(),
            "op-tee".to_string(),
            "tf-a".to_string(),
            "hab".to_string(),
        ],
    }
}
