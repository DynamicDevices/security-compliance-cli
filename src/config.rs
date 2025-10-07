use crate::cli::{Cli, OutputFormat, MachineType};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub target: TargetConfig,
    pub output: OutputConfig,
    pub tests: TestConfig,
    pub thresholds: ThresholdConfig,
    pub machine: Option<MachineConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub ssh_key_path: Option<String>,
    pub timeout: u64,
    pub ssh_multiplex: bool,
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
        config.target.host = cli.host.clone();
        config.target.port = cli.port;
        config.target.user = cli.user.clone();
        config.target.password = cli.password.clone();
        config.target.ssh_key_path = cli
            .identity_file
            .as_ref()
            .map(|p| p.to_string_lossy().to_string());
        config.target.timeout = cli.timeout;
        config.output.verbose = cli.verbose;
        config.output.format = match cli.format {
            OutputFormat::Human => "human".to_string(),
            OutputFormat::Json => "json".to_string(),
            OutputFormat::Junit => "junit".to_string(),
            OutputFormat::Markdown => "markdown".to_string(),
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
                auto_detect: false,
                hardware_features: get_machine_features(machine_type),
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target: TargetConfig {
                host: "192.168.0.36".to_string(),
                port: 22,
                user: "fio".to_string(),
                password: "fio".to_string(),
                ssh_key_path: None,
                timeout: 30,
                ssh_multiplex: true,
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
            machine: None,
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
