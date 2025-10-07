use crate::{
    error::Result,
    target::Target,
    tests::{create_test_result, SecurityTest, TestResult, TestStatus},
};
use async_trait::async_trait;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum HardwareSecurityTests {
    EdgeLockEnclave,
    SecureEnclaveStatus,
    HardwareRootOfTrust,
    CryptoAcceleration,
    RandomNumberGenerator,
}

#[async_trait]
impl SecurityTest for HardwareSecurityTests {
    async fn run(&self, target: &mut Target) -> Result<TestResult> {
        let start_time = Instant::now();

        let result = match self {
            Self::EdgeLockEnclave => self.test_edgelock_enclave(target).await,
            Self::SecureEnclaveStatus => self.test_secure_enclave_status(target).await,
            Self::HardwareRootOfTrust => self.test_hardware_root_of_trust(target).await,
            Self::CryptoAcceleration => self.test_crypto_acceleration(target).await,
            Self::RandomNumberGenerator => self.test_random_number_generator(target).await,
        };

        let duration = start_time.elapsed();

        match result {
            Ok((status, message, details)) => Ok(create_test_result(
                self.test_id(),
                self.test_name(),
                self.category(),
                status,
                &message,
                details,
                duration,
            )),
            Err(e) => Ok(create_test_result(
                self.test_id(),
                self.test_name(),
                self.category(),
                TestStatus::Error,
                &format!("Test execution failed: {}", e),
                None,
                duration,
            )),
        }
    }

    fn test_id(&self) -> &str {
        match self {
            Self::EdgeLockEnclave => "hardware_001",
            Self::SecureEnclaveStatus => "hardware_002",
            Self::HardwareRootOfTrust => "hardware_003",
            Self::CryptoAcceleration => "hardware_004",
            Self::RandomNumberGenerator => "hardware_005",
        }
    }

    fn test_name(&self) -> &str {
        match self {
            Self::EdgeLockEnclave => "EdgeLock Enclave (ELE)",
            Self::SecureEnclaveStatus => "Secure Enclave Status",
            Self::HardwareRootOfTrust => "Hardware Root of Trust",
            Self::CryptoAcceleration => "Crypto Hardware Acceleration",
            Self::RandomNumberGenerator => "Hardware RNG",
        }
    }

    fn category(&self) -> &str {
        "hardware"
    }

    fn description(&self) -> &str {
        match self {
            Self::EdgeLockEnclave => "Validates the i.MX93 EdgeLock Enclave (ELE) hardware security module is operational. ELE provides secure key storage, cryptographic operations, and secure boot attestation. Essential for hardware-based security features and compliance with security standards.",
            Self::SecureEnclaveStatus => "Verifies the secure enclave hardware is properly initialized and accessible. Tests enclave functionality and ensures secure world isolation is working correctly for sensitive operations like key generation and secure storage.",
            Self::HardwareRootOfTrust => "Confirms the hardware root of trust is established and functional. Checks for secure boot fuses, OTP (One-Time Programmable) memory, and AHAB (Advanced High Assurance Boot) indicators that form the foundation of system security.",
            Self::CryptoAcceleration => "Validates hardware cryptographic acceleration capabilities through CAAM (Cryptographic Acceleration and Assurance Module). Hardware crypto acceleration improves performance and security for encryption, decryption, and digital signature operations.",
            Self::RandomNumberGenerator => "Ensures the hardware random number generator (TRNG - True Random Number Generator) is functional and providing sufficient entropy. Critical for cryptographic key generation, secure communications, and preventing predictable security vulnerabilities.",
        }
    }
}

impl HardwareSecurityTests {
    async fn test_edgelock_enclave(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        let mut details = Vec::new();
        let mut indicators = Vec::new();
        let mut warnings = Vec::new();

        // Check for EdgeLock Enclave in dmesg with comprehensive patterns
        let ele_dmesg = target
            .execute_command("dmesg | grep -i 'ele\\|edgelock\\|s4muap\\|mu.*imx93\\|sentinel'")
            .await?;
        if !ele_dmesg.stdout.is_empty() {
            indicators.push("ELE kernel messages found");
            details.push(format!("ELE dmesg output:\n{}", ele_dmesg.stdout));
        }

        // Check for ELE device nodes
        let ele_devices = target
            .execute_command("ls -la /dev/ | grep -E 'ele|s4muap|mu[0-9]'")
            .await?;
        if !ele_devices.stdout.is_empty() {
            indicators.push("ELE device nodes present");
            details.push(format!("ELE devices:\n{}", ele_devices.stdout));
        }

        // Check for ELE in /proc/devices
        let ele_proc = target
            .execute_command("cat /proc/devices | grep -i 'ele\\|s4muap'")
            .await?;
        if !ele_proc.stdout.is_empty() {
            indicators.push("ELE in proc devices");
            details.push(format!("ELE proc devices:\n{}", ele_proc.stdout));
        }

        // Check for i.MX93 specific ELE firmware loading
        let ele_firmware = target
            .execute_command("dmesg | grep -i 'firmware.*mx93\\|mx93.*firmware\\|ahab.*mx93'")
            .await?;
        if !ele_firmware.stdout.is_empty() {
            indicators.push("ELE firmware loading detected");
            details.push(format!("ELE firmware messages:\n{}", ele_firmware.stdout));
        }

        // Check for ELE-related kernel modules
        let ele_modules = target
            .execute_command("lsmod | grep -E 'imx_mu|s4|ele'")
            .await?;
        if !ele_modules.stdout.is_empty() {
            indicators.push("ELE kernel modules loaded");
            details.push(format!("ELE modules:\n{}", ele_modules.stdout));
        }

        // Check for secure world communication
        let secure_world = target
            .execute_command("dmesg | grep -i 'secure.*world\\|trustzone\\|optee.*imx'")
            .await?;
        if !secure_world.stdout.is_empty() {
            indicators.push("Secure world communication active");
            details.push(format!("Secure world messages:\n{}", secure_world.stdout));
        }

        // Check ELE status via device tree if available
        let dt_check = target.execute_command("find /proc/device-tree -name '*ele*' -o -name '*s4*' -o -name '*mu*' 2>/dev/null | head -5").await?;
        if !dt_check.stdout.is_empty() {
            indicators.push("ELE device tree entries found");
            details.push(format!("Device tree ELE entries:\n{}", dt_check.stdout));
        }

        // Look for ELE management tools warnings
        let ele_tools = target
            .execute_command(
                "which ele_mu_ctl simple-ele-test 2>/dev/null || echo 'tools_not_found'",
            )
            .await?;
        if ele_tools.stdout.contains("tools_not_found") {
            warnings.push("ELE management tools not installed (optional for operation)");
        } else {
            indicators.push("ELE management tools available");
            details.push(format!("ELE tools: {}", ele_tools.stdout));
        }

        // Detailed summary
        let _summary = if indicators.is_empty() {
            "No EdgeLock Enclave indicators found".to_string()
        } else {
            format!("EdgeLock Enclave indicators: {}", indicators.join(", "))
        };

        if !warnings.is_empty() {
            details.push(format!("\nInformational notes:\n{}", warnings.join("\n")));
        }

        // Determine status based on indicators
        if indicators.len() >= 3 {
            Ok((
                TestStatus::Passed,
                format!("EdgeLock Enclave active ({} indicators)", indicators.len()),
                Some(details.join("\n\n")),
            ))
        } else if !indicators.is_empty() {
            Ok((
                TestStatus::Warning,
                format!("ELE partially detected ({} indicators)", indicators.len()),
                Some(details.join("\n\n")),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                "EdgeLock Enclave not detected".to_string(),
                Some(details.join("\n\n")),
            ))
        }
    }

    async fn test_secure_enclave_status(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Run ELE test if available
        let ele_test = target
            .execute_command("simple-ele-test info 2>/dev/null || echo 'test_not_available'")
            .await?;

        // Check for secure enclave services
        let enclave_services = target
            .execute_command("systemctl list-units | grep -i 'enclave\\|secure'")
            .await?;

        let details = format!(
            "ELE test: {}\nEnclave services: {}",
            ele_test.stdout, enclave_services.stdout
        );

        if ele_test.stdout.contains("ELE") && !ele_test.stdout.contains("test_not_available") {
            Ok((
                TestStatus::Passed,
                "Secure enclave test successful".to_string(),
                Some(details),
            ))
        } else if !enclave_services.stdout.is_empty() {
            Ok((
                TestStatus::Warning,
                "Enclave services detected but test unavailable".to_string(),
                Some(details),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                "Secure enclave test tools not available - install ELE management tools"
                    .to_string(),
                Some(details),
            ))
        }
    }

    async fn test_hardware_root_of_trust(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check for hardware root of trust indicators
        let rot_check = target
            .execute_command("dmesg | grep -i 'root.*trust\\|fuse\\|otp\\|hab\\|ahab'")
            .await?;

        // Check for secure boot fuses
        let fuse_check = target
            .execute_command("find /sys -name '*fuse*' -o -name '*otp*' 2>/dev/null | head -5")
            .await?;

        let details = format!(
            "RoT indicators: {}\nFuse/OTP: {}",
            rot_check.stdout, fuse_check.stdout
        );

        if rot_check.stdout.contains("AHAB") || rot_check.stdout.contains("fuse") {
            Ok((
                TestStatus::Passed,
                "Hardware root of trust indicators found".to_string(),
                Some(details),
            ))
        } else if !fuse_check.stdout.is_empty() {
            Ok((
                TestStatus::Warning,
                "Fuse/OTP hardware present".to_string(),
                Some(details),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                "No hardware root of trust detected".to_string(),
                Some(details),
            ))
        }
    }

    async fn test_crypto_acceleration(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check for crypto hardware
        let crypto_hw = target
            .execute_command("cat /proc/crypto | grep -A5 -B5 'driver.*caam\\|driver.*imx'")
            .await?;

        // Check for hardware crypto modules
        let crypto_modules = target
            .execute_command("lsmod | grep -E 'caam\\|imx.*crypt'")
            .await?;

        // Check for crypto devices
        let crypto_devices = target
            .execute_command("ls -la /dev/ | grep -i crypto")
            .await?;

        let mut details = Vec::new();
        details.push(format!("Crypto hardware: {}", crypto_hw.stdout));
        details.push(format!("Crypto modules: {}", crypto_modules.stdout));
        details.push(format!("Crypto devices: {}", crypto_devices.stdout));

        if crypto_hw.stdout.contains("caam") || crypto_hw.stdout.contains("imx") {
            Ok((
                TestStatus::Passed,
                "Hardware crypto acceleration detected".to_string(),
                Some(details.join("\n")),
            ))
        } else if !crypto_modules.stdout.is_empty() {
            Ok((
                TestStatus::Warning,
                "Crypto modules loaded but hardware unclear".to_string(),
                Some(details.join("\n")),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                "No hardware crypto acceleration detected".to_string(),
                Some(details.join("\n")),
            ))
        }
    }

    async fn test_random_number_generator(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check for hardware RNG
        let hwrng = target
            .execute_command("cat /proc/sys/kernel/random/entropy_avail")
            .await?;

        // Check for RNG devices
        let rng_devices = target
            .execute_command("ls -la /dev/*random* /dev/hwrng 2>/dev/null || echo 'not_found'")
            .await?;

        // Check RNG quality
        let rng_quality = target
            .execute_command(
                "cat /sys/class/misc/hw_random/rng_current 2>/dev/null || echo 'not_available'",
            )
            .await?;

        let entropy: u32 = hwrng.stdout.trim().parse().unwrap_or(0);

        let details = format!(
            "Entropy available: {}\nRNG devices: {}\nRNG current: {}",
            entropy, rng_devices.stdout, rng_quality.stdout
        );

        if entropy > 1000 && rng_devices.stdout.contains("hwrng") {
            Ok((
                TestStatus::Passed,
                format!("Hardware RNG active (entropy: {})", entropy),
                Some(details),
            ))
        } else if entropy > 500 {
            Ok((
                TestStatus::Warning,
                format!("RNG available but low entropy ({})", entropy),
                Some(details),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                format!("Insufficient entropy ({})", entropy),
                Some(details),
            ))
        }
    }
}
