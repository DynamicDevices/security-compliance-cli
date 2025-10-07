/*
 * Security Compliance CLI - Machine Detection and Filtering
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::cli::MachineType;
use crate::communication::CommunicationChannel;
use crate::config::MachineConfig;
use crate::error::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct MachineInfo {
    pub machine_type: Option<MachineType>,
    pub detected_features: Vec<String>,
    pub cpu_info: String,
    pub board_info: Option<String>,
}

pub struct MachineDetector<'a> {
    comm_channel: &'a mut dyn CommunicationChannel,
}

impl<'a> MachineDetector<'a> {
    pub fn new(comm_channel: &'a mut dyn CommunicationChannel) -> Self {
        Self { comm_channel }
    }

    /// Detect the machine type based on hardware characteristics
    pub async fn detect_machine(&mut self) -> Result<MachineInfo> {
        let cpu_info = self.get_cpu_info().await?;
        let board_info = self.get_board_info().await.ok();
        let detected_features = self.detect_hardware_features().await?;

        let machine_type = self.determine_machine_type(&cpu_info, &board_info, &detected_features);

        Ok(MachineInfo {
            machine_type,
            detected_features,
            cpu_info,
            board_info,
        })
    }

    async fn get_cpu_info(&mut self) -> Result<String> {
        let output = self
            .comm_channel
            .execute_command(
                "cat /proc/cpuinfo | grep -E '(model name|Hardware|Revision)' | head -3",
            )
            .await?;
        Ok(output.stdout)
    }

    async fn get_board_info(&mut self) -> Result<String> {
        let output = self
            .comm_channel
            .execute_command("cat /proc/device-tree/model 2>/dev/null || echo 'Unknown'")
            .await?;
        Ok(output.stdout.trim().to_string())
    }

    async fn detect_hardware_features(&mut self) -> Result<Vec<String>> {
        let mut features = Vec::new();

        // Check for i.MX93 EdgeLock Enclave
        if self.check_feature_exists("/dev/ele_mu").await {
            features.push("edgelock-enclave".to_string());
        }

        // Check for CAAM (Cryptographic Acceleration and Assurance Module)
        if self.check_feature_exists("/dev/caam*").await {
            features.push("caam".to_string());
        }

        // Check for secure boot indicators
        if self.check_secure_boot().await {
            features.push("secure-boot".to_string());
        }

        // Check for TrustZone/OP-TEE
        if self.check_feature_exists("/dev/tee*").await {
            features.push("op-tee".to_string());
            features.push("trustzone".to_string());
        }

        // Check for PCF2131 RTC (specific to i.MX93 Jaguar E-Ink)
        if self.check_pcf2131_rtc().await {
            features.push("pcf2131-rtc".to_string());
        }

        // Check for specific SoC types
        let cpu_info = self.get_cpu_info().await?;
        if cpu_info.contains("i.MX93") || cpu_info.contains("imx93") {
            features.push("imx93".to_string());
        } else if cpu_info.contains("i.MX8MM") || cpu_info.contains("imx8mm") {
            features.push("imx8mm".to_string());
        }

        Ok(features)
    }

    async fn check_feature_exists(&mut self, path: &str) -> bool {
        let command = format!("ls {} >/dev/null 2>&1", path);
        if let Ok(output) = self.comm_channel.execute_command(&command).await {
            output.exit_code == 0
        } else {
            false
        }
    }

    async fn check_secure_boot(&mut self) -> bool {
        // Check for secure boot indicators in various locations
        let checks = vec![
            "cat /proc/cmdline | grep -q 'secure'",
            "dmesg | grep -qi 'secure boot'",
            "ls /sys/firmware/efi/efivars/*SecureBoot* >/dev/null 2>&1",
        ];

        for check in checks {
            if let Ok(output) = self.comm_channel.execute_command(check).await {
                if output.exit_code == 0 {
                    return true;
                }
            }
        }
        false
    }

    async fn check_pcf2131_rtc(&mut self) -> bool {
        // Check for PCF2131 RTC in multiple ways
        let checks = vec![
            // Check for PCF2131 in I2C device tree
            "find /sys/bus/i2c/devices -name '*pcf2131*' | head -1",
            // Check for PCF2131 in device tree
            "find /proc/device-tree -name '*pcf2131*' | head -1", 
            // Check dmesg for PCF2131 messages
            "dmesg | grep -i pcf2131 | head -1",
            // Check for RTC device with PCF2131 driver
            "cat /sys/class/rtc/rtc*/name 2>/dev/null | grep -i pcf2131",
            // Check I2C bus for PCF2131 address (typically 0x53)
            "i2cdetect -y 0 2>/dev/null | grep -E '53|UU' || i2cdetect -y 1 2>/dev/null | grep -E '53|UU'",
        ];

        for check in checks {
            if let Ok(output) = self.comm_channel.execute_command(check).await {
                if output.exit_code == 0 && !output.stdout.trim().is_empty() {
                    return true;
                }
            }
        }
        false
    }

    fn determine_machine_type(
        &self,
        _cpu_info: &str,
        board_info: &Option<String>,
        features: &[String],
    ) -> Option<MachineType> {
        // Check for i.MX93 Jaguar E-Ink
        if features.contains(&"imx93".to_string())
            && features.contains(&"edgelock-enclave".to_string())
        {
            if let Some(board) = board_info {
                if board.to_lowercase().contains("jaguar") && board.to_lowercase().contains("eink")
                {
                    return Some(MachineType::Imx93JaguarEink);
                }
            }
            // Additional check: PCF2131 RTC is specific to E-Ink variant
            if features.contains(&"pcf2131-rtc".to_string()) {
                return Some(MachineType::Imx93JaguarEink);
            }
            // Fallback to i.MX93 detection
            return Some(MachineType::Imx93JaguarEink);
        }

        // Check for i.MX8MM Jaguar Sentai
        if features.contains(&"imx8mm".to_string()) {
            if let Some(board) = board_info {
                if board.to_lowercase().contains("jaguar")
                    && board.to_lowercase().contains("sentai")
                {
                    return Some(MachineType::Imx8mmJaguarSentai);
                }
            }
            // Fallback to i.MX8MM detection
            return Some(MachineType::Imx8mmJaguarSentai);
        }

        None
    }
}

/// Filter tests based on machine compatibility
pub fn filter_tests_for_machine(
    test_names: &[String],
    machine_config: &Option<MachineConfig>,
) -> Vec<String> {
    let Some(machine_config) = machine_config else {
        // No machine specified, return all tests
        return test_names.to_vec();
    };

    let machine_features = &machine_config.hardware_features;
    let mut filtered_tests = Vec::new();

    for test_name in test_names {
        if is_test_compatible_with_machine(test_name, machine_features) {
            filtered_tests.push(test_name.clone());
        }
    }

    filtered_tests
}

fn is_test_compatible_with_machine(test_name: &str, machine_features: &[String]) -> bool {
    // Define test compatibility rules
    let compatibility_rules: HashMap<&str, Vec<&str>> = HashMap::from([
        // Hardware tests that require specific features
        ("hardware_001", vec!["edgelock-enclave"]), // EdgeLock Enclave (ELE) - i.MX93 only
        ("hardware_002", vec!["trustzone", "op-tee"]), // Secure Enclave Status
        ("hardware_003", vec!["secure-boot"]),      // Hardware Root of Trust
        ("hardware_004", vec!["caam"]),             // Crypto Hardware Acceleration
        ("hardware_005", vec!["caam"]),             // Hardware RNG
        ("hardware_006", vec!["pcf2131-rtc"]),      // PCF2131 RTC functionality - i.MX93 E-Ink only
        // Boot tests that may be SoC-specific
        ("boot_001", vec!["secure-boot"]), // Secure Boot Enabled
        ("boot_005", vec!["op-tee"]),      // OP-TEE Signature Verification
        ("boot_006", vec!["tf-a"]),        // TF-A Signature Verification
        // Runtime tests that might use RTC
        ("runtime_009", vec!["pcf2131-rtc"]), // Time synchronization and RTC accuracy
        // i.MX93 specific tests
        ("hardware_001", vec!["imx93"]), // EdgeLock Enclave is i.MX93 specific
        // i.MX8MM specific tests (HAB vs ELE)
        ("boot_hab_verification", vec!["imx8mm", "hab"]), // HAB verification for i.MX8MM
    ]);

    // Check if test has specific requirements
    if let Some(required_features) = compatibility_rules.get(test_name) {
        // Test requires specific features - check if machine has them
        for required_feature in required_features {
            if !machine_features.contains(&required_feature.to_string()) {
                return false;
            }
        }
    }

    // If no specific requirements or all requirements met, test is compatible
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_machine_feature_filtering() {
        let all_tests = vec![
            "hardware_001".to_string(), // EdgeLock Enclave - i.MX93 only
            "hardware_002".to_string(), // Secure Enclave - requires TrustZone
            "runtime_001".to_string(),  // Generic runtime test
        ];

        // Test i.MX93 Jaguar E-Ink machine
        let imx93_config = MachineConfig {
            machine_type: "imx93-jaguar-eink".to_string(),
            auto_detect: false,
            hardware_features: vec![
                "imx93".to_string(),
                "edgelock-enclave".to_string(),
                "trustzone".to_string(),
                "op-tee".to_string(),
                "pcf2131-rtc".to_string(),
            ],
        };

        let filtered = filter_tests_for_machine(&all_tests, &Some(imx93_config));
        assert!(filtered.contains(&"hardware_001".to_string())); // Should include ELE test
        assert!(filtered.contains(&"hardware_002".to_string())); // Should include TrustZone test
        assert!(filtered.contains(&"runtime_001".to_string())); // Should include generic test

        // Test i.MX8MM machine (no EdgeLock Enclave)
        let imx8mm_config = MachineConfig {
            machine_type: "imx8mm-jaguar-sentai".to_string(),
            auto_detect: false,
            hardware_features: vec![
                "imx8mm".to_string(),
                "trustzone".to_string(),
                "op-tee".to_string(),
                "hab".to_string(),
            ],
        };

        let filtered = filter_tests_for_machine(&all_tests, &Some(imx8mm_config));
        assert!(!filtered.contains(&"hardware_001".to_string())); // Should exclude ELE test
        assert!(filtered.contains(&"hardware_002".to_string())); // Should include TrustZone test
        assert!(filtered.contains(&"runtime_001".to_string())); // Should include generic test
    }
}
