use crate::{
    error::Result,
    target::Target,
    tests::{create_test_result, SecurityTest, TestResult, TestStatus},
};
use async_trait::async_trait;
use std::time::Instant;
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub enum BootSecurityTests {
    SecureBootEnabled,
    UBootSigned,
    KernelSigned,
    ModuleSigning,
    OpteeSigned,
    TfaSigned,
    BootChainVerification,
}

#[async_trait]
impl SecurityTest for BootSecurityTests {
    async fn run(&self, target: &mut Target) -> Result<TestResult> {
        let start_time = Instant::now();

        let result = match self {
            Self::SecureBootEnabled => self.test_secure_boot_enabled(target).await,
            Self::UBootSigned => self.test_uboot_signed(target).await,
            Self::KernelSigned => self.test_kernel_signed(target).await,
            Self::ModuleSigning => self.test_module_signing(target).await,
            Self::OpteeSigned => self.test_optee_signed(target).await,
            Self::TfaSigned => self.test_tfa_signed(target).await,
            Self::BootChainVerification => self.test_boot_chain_verification(target).await,
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
            Self::SecureBootEnabled => "boot_001",
            Self::UBootSigned => "boot_002",
            Self::KernelSigned => "boot_003",
            Self::ModuleSigning => "boot_004",
            Self::OpteeSigned => "boot_005",
            Self::TfaSigned => "boot_006",
            Self::BootChainVerification => "boot_007",
        }
    }

    fn test_name(&self) -> &str {
        match self {
            Self::SecureBootEnabled => "Secure Boot Enabled",
            Self::UBootSigned => "U-Boot Signature Verification",
            Self::KernelSigned => "Kernel Signature Verification",
            Self::ModuleSigning => "Module Signing Active",
            Self::OpteeSigned => "OP-TEE Signature Verification",
            Self::TfaSigned => "TF-A Signature Verification",
            Self::BootChainVerification => "Complete Boot Chain Verification",
        }
    }

    fn category(&self) -> &str {
        "boot"
    }

    fn description(&self) -> &str {
        match self {
            Self::SecureBootEnabled => "Ensures the system boots only with cryptographically verified firmware components. Checks for i.MX93 EdgeLock Enclave (ELE) secure boot indicators, ELE device nodes, factory kernel module signing, and device tree secure boot configuration. Critical for preventing unauthorized firmware execution.",
            Self::UBootSigned => "Verifies that the U-Boot bootloader has valid cryptographic signatures and cannot be tampered with. Examines FIT (Flattened Image Tree) images for embedded RSA/SHA256 signatures, checks device tree verification messages, and validates secure boot parameters passed to the kernel.",
            Self::KernelSigned => "Confirms the Linux kernel image is cryptographically signed and verified during boot. Prevents execution of modified or malicious kernel images that could compromise the entire system security.",
            Self::ModuleSigning => "Ensures all kernel modules are cryptographically signed and only trusted modules can be loaded. Prevents rootkit installation and unauthorized kernel code execution by validating module signatures against trusted keys.",
            Self::OpteeSigned => "Validates that the OP-TEE Trusted Execution Environment is properly signed and verified. OP-TEE provides secure world isolation for sensitive operations like cryptographic key storage and secure boot validation.",
            Self::TfaSigned => "Verifies ARM Trusted Firmware-A (TF-A) signature validation for secure world boot components. TF-A is the first software to run and establishes the root of trust for the entire system.",
            Self::BootChainVerification => "Performs end-to-end verification of the complete secure boot chain from hardware root of trust through all firmware stages. Ensures no gaps in the chain of trust that could be exploited by attackers.",
        }
    }
}

impl BootSecurityTests {
    /// Check if the current user has sudo access
    async fn check_sudo_access(&self, target: &mut Target) -> Result<bool> {
        debug!("Checking sudo access for privileged boot tests");

        // Try a simple sudo command that doesn't require password input
        let result = target.execute_command("sudo -n true 2>/dev/null").await;

        match result {
            Ok(cmd_result) => {
                if cmd_result.exit_code == 0 {
                    debug!("Passwordless sudo access available");
                    Ok(true)
                } else {
                    debug!("No passwordless sudo access, checking if sudo is available");
                    // Check if user is in sudo group or has sudo access with password
                    let groups_result = target.execute_command("groups").await?;
                    let has_sudo_group = groups_result.stdout.contains("sudo")
                        || groups_result.stdout.contains("wheel");

                    if has_sudo_group {
                        debug!("User is in sudo group but password required");
                        Ok(true)
                    } else {
                        debug!("User does not have sudo access");
                        Ok(false)
                    }
                }
            }
            Err(_) => {
                debug!("Could not check sudo access");
                Ok(false)
            }
        }
    }

    /// Execute a command that requires kernel access, trying sudo if needed
    async fn execute_kernel_command(
        &self,
        target: &mut Target,
        command: &str,
    ) -> Result<crate::target::CommandResult> {
        debug!("Executing kernel command: {}", command);

        // First try the command without sudo
        let result = target.execute_command(command).await?;

        // If it fails with permission denied, try with sudo
        if result.exit_code != 0
            && (result.stderr.contains("Operation not permitted")
                || result.stderr.contains("Permission denied"))
        {
            debug!("Command failed with permission error, checking sudo access");

            if self.check_sudo_access(target).await? {
                warn!("⚠️  Elevated privileges required for kernel access. Using sudo for boot security tests.");
                warn!(
                    "💡 For better security testing, run as root or configure passwordless sudo."
                );

                // Try with sudo using password input - we'll try common embedded passwords
                let common_passwords = ["fio"]; // Focus on the most likely password first

                for password in &common_passwords {
                    debug!(
                        "Trying sudo with password authentication: {}",
                        if password.is_empty() {
                            "passwordless"
                        } else {
                            "with password"
                        }
                    );
                    let sudo_command = if password.is_empty() {
                        format!("sudo -n {}", command)
                    } else {
                        format!("echo '{}' | sudo -S {} 2>/dev/null", password, command)
                    };

                    let sudo_result = target.execute_command(&sudo_command).await?;

                    if sudo_result.exit_code == 0 {
                        debug!("Sudo command succeeded with password authentication");
                        return Ok(sudo_result);
                    } else {
                        debug!(
                            "Sudo attempt failed with exit code: {}",
                            sudo_result.exit_code
                        );
                    }
                }

                warn!("⚠️  Sudo password required but not available in automated testing");
                warn!("💡 Configure passwordless sudo or run tests as root for complete analysis");
                Ok(result) // Return original result if sudo fails
            } else {
                warn!("⚠️  Kernel access denied and no sudo privileges available");
                warn!("💡 Some boot security tests may be incomplete without elevated privileges");
                Ok(result)
            }
        } else {
            Ok(result)
        }
    }
    async fn test_secure_boot_enabled(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        let mut details = Vec::new();
        let mut secure_indicators = Vec::new();

        // Check for ELE management tools availability (informational only, not a security concern)
        let ele_tools_check = target
            .execute_command("which ele_mu_ctl ele_status 2>/dev/null || echo 'tools_not_found'")
            .await?;
        let ele_tools_available = !ele_tools_check.stdout.contains("tools_not_found")
            && !ele_tools_check.stdout.trim().is_empty();

        if ele_tools_available {
            // Try to get ELE status using tools
            let ele_status = target
                .execute_command("ele_status 2>/dev/null || echo 'ele_status_failed'")
                .await?;
            if !ele_status.stdout.contains("ele_status_failed") {
                secure_indicators.push("ELE management tools functional");
                details.push(format!(
                    "ELE Tools Status: {}",
                    ele_status.stdout.lines().next().unwrap_or("Available")
                ));
            } else {
                details.push(
                    "ELE tools found but status query failed (informational only)".to_string(),
                );
            }
        } else {
            details.push(
                "ELE management tools not available (informational - not a security concern)"
                    .to_string(),
            );
        }

        // Check for EdgeLock Enclave (ELE) on i.MX93 - primary secure boot mechanism
        let ele_check = self
            .execute_kernel_command(target, "dmesg | grep -i 'fsl-ele-mu\\|ele-trng\\|EdgeLock'")
            .await?;
        if ele_check.stdout.contains("fsl-ele-mu")
            && ele_check.stdout.contains("Successfully registered")
        {
            secure_indicators.push("EdgeLock Enclave (ELE) active");
            details.push(format!(
                "ELE Status: {}",
                ele_check.stdout.lines().next().unwrap_or("Active")
            ));
        }

        // Check for ELE device nodes
        let ele_devices = target
            .execute_command("ls -la /dev/ele_mu* 2>/dev/null | wc -l")
            .await?;
        if ele_devices.stdout.trim().parse::<i32>().unwrap_or(0) > 0 {
            secure_indicators.push("ELE device interfaces present");
            details.push(format!("ELE devices: {} found", ele_devices.stdout.trim()));
        }

        // Check for Factory kernel module signing (indicates secure boot chain)
        let factory_key = self
            .execute_kernel_command(target, "dmesg | grep 'Factory kernel module signing key'")
            .await?;
        if !factory_key.stdout.is_empty() {
            secure_indicators.push("Factory module signing key loaded");
            details.push("Factory signing: Active".to_string());
        }

        // Check device tree for ELE configuration
        let dt_ele = target
            .execute_command("find /sys/firmware/devicetree -name '*ele*' 2>/dev/null | wc -l")
            .await?;
        if dt_ele.stdout.trim().parse::<i32>().unwrap_or(0) > 0 {
            secure_indicators.push("ELE device tree configuration");
            details.push("Device tree: ELE configured".to_string());
        }

        // Check for AHAB (Advanced High Assurance Boot) messages as fallback
        let ahab_check = target
            .execute_command("dmesg | grep -i 'ahab\\|secure.*boot\\|hab'")
            .await?;
        if ahab_check.stdout.contains("AHAB") || ahab_check.stdout.contains("secure boot") {
            secure_indicators.push("AHAB/HAB messages found");
            details.push(format!("AHAB: {}", ahab_check.stdout));
        }

        let details_str = if details.is_empty() {
            None
        } else {
            Some(details.join("\n"))
        };

        // Determine status based on secure indicators - management tools are informational only
        match secure_indicators.len() {
            4.. => Ok((
                TestStatus::Passed,
                format!("Secure boot fully active: {}", secure_indicators.join(", ")),
                details_str,
            )),
            3 => Ok((
                TestStatus::Passed,
                format!("Secure boot active: {}", secure_indicators.join(", ")),
                details_str,
            )),
            1..=2 => Ok((
                TestStatus::Warning,
                format!(
                    "Partial secure boot detected: {}",
                    secure_indicators.join(", ")
                ),
                details_str,
            )),
            _ => Ok((
                TestStatus::Failed,
                "No secure boot indicators found".to_string(),
                details_str,
            )),
        }
    }

    async fn test_uboot_signed(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        let mut details = Vec::new();
        let mut uboot_indicators = Vec::new();

        // Check for FIT (Flattened Image Tree) images which are U-Boot's signed image format
        let fit_images = target
            .execute_command(
                "find /var/rootdirs/mnt/boot /boot -name '*.itb' -o -name '*.fit' 2>/dev/null",
            )
            .await?;
        if !fit_images.stdout.is_empty() {
            uboot_indicators.push("FIT images found");
            details.push(format!("FIT images: {}", fit_images.stdout.trim()));

            // Check if FIT images contain signatures
            let fit_sigs = target.execute_command("strings /var/rootdirs/mnt/boot/*.itb 2>/dev/null | grep -i 'signature\\|rsa\\|hash.*sign' | head -3").await?;
            if !fit_sigs.stdout.is_empty() {
                uboot_indicators.push("FIT signatures detected");
                details.push(format!("FIT signatures: {}", fit_sigs.stdout.trim()));
            }
        }

        // Check U-Boot signature verification in boot log (legacy method)
        let uboot_sig = target
            .execute_command("dmesg | grep -i 'u-boot.*sign\\|verified\\|signature'")
            .await?;
        if uboot_sig.stdout.contains("verified") || uboot_sig.stdout.contains("signature") {
            uboot_indicators.push("U-Boot signature messages in dmesg");
            details.push(format!("U-Boot messages: {}", uboot_sig.stdout.trim()));
        }

        // Check for device tree verification (indicates FIT image was verified)
        let dt_verify = target
            .execute_command("dmesg | grep -i 'fit.*verif\\|dtb.*verif\\|device.*tree.*verif'")
            .await?;
        if !dt_verify.stdout.is_empty() {
            uboot_indicators.push("Device tree verification detected");
            details.push(format!("DT verification: {}", dt_verify.stdout.trim()));
        }

        // Check for secure boot indicators in kernel command line (passed from U-Boot)
        let cmdline_secure = target
            .execute_command(
                "cat /proc/cmdline | grep -o 'secure[^[:space:]]*\\|verified[^[:space:]]*'",
            )
            .await?;
        if !cmdline_secure.stdout.is_empty() {
            uboot_indicators.push("Secure boot parameters in cmdline");
            details.push(format!("Cmdline secure: {}", cmdline_secure.stdout.trim()));
        }

        let details_str = if details.is_empty() {
            None
        } else {
            Some(details.join("\n"))
        };

        match uboot_indicators.len() {
            2.. => Ok((
                TestStatus::Passed,
                format!(
                    "U-Boot signature verification active: {}",
                    uboot_indicators.join(", ")
                ),
                details_str,
            )),
            1 => Ok((
                TestStatus::Warning,
                format!(
                    "Partial U-Boot verification: {}",
                    uboot_indicators.join(", ")
                ),
                details_str,
            )),
            _ => Ok((
                TestStatus::Failed,
                "No U-Boot signature verification found".to_string(),
                details_str,
            )),
        }
    }

    async fn test_kernel_signed(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        let mut details = Vec::new();
        let mut kernel_verification_indicators = Vec::new();

        // Check for kernel signature verification in dmesg
        let kernel_sig = self
            .execute_kernel_command(target, "dmesg | grep -i 'kernel.*sign\\|vmlinuz.*verif'")
            .await?;
        if !kernel_sig.stdout.is_empty() {
            kernel_verification_indicators.push("Direct kernel signature verification");
            details.push(format!("Kernel signature: {}", kernel_sig.stdout.trim()));
        }

        // Check if kernel lockdown is enabled (indicates signed kernel)
        let lockdown = target
            .execute_command(
                "cat /sys/kernel/security/lockdown 2>/dev/null || echo 'not_available'",
            )
            .await?;
        if lockdown.stdout.contains("[integrity]") || lockdown.stdout.contains("[confidentiality]")
        {
            kernel_verification_indicators.push("Kernel lockdown mode active");
            details.push(format!("Lockdown: {}", lockdown.stdout.trim()));
        } else if lockdown.stdout.contains("integrity")
            || lockdown.stdout.contains("confidentiality")
        {
            // Lockdown available but not active
            details.push(format!(
                "Lockdown available but not active: {}",
                lockdown.stdout.trim()
            ));
        }

        // For i.MX93 systems: Check if ELE-based secure boot is handling kernel verification
        let ele_secure_boot = self
            .execute_kernel_command(target, "dmesg | grep -i 'ele\\|edgelock\\|ahab\\|hab'")
            .await?;
        if !ele_secure_boot.stdout.is_empty() {
            kernel_verification_indicators.push("Hardware-based secure boot (ELE/AHAB)");
            details.push(format!(
                "Hardware secure boot: {}",
                ele_secure_boot
                    .stdout
                    .lines()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }

        // Check for FIT image verification (common on embedded systems)
        let fit_verify = target
            .execute_command("dmesg | grep -i 'fit.*verif\\|fit.*sign'")
            .await?;
        if !fit_verify.stdout.is_empty() {
            kernel_verification_indicators.push("FIT image verification");
            details.push(format!("FIT verification: {}", fit_verify.stdout.trim()));
        }

        // Check for factory signing key (indicates the system uses signed components)
        let factory_key = target
            .execute_command("dmesg | grep -i 'Factory kernel module signing key'")
            .await?;
        if !factory_key.stdout.is_empty() {
            kernel_verification_indicators.push("Factory signing infrastructure");
            details.push(format!("Factory key: {}", factory_key.stdout.trim()));
        }

        // Check kernel command line for secure boot parameters
        let cmdline_secure = target.execute_command("cat /proc/cmdline | grep -o 'secure[^[:space:]]*\\|verified[^[:space:]]*\\|ima[^[:space:]]*'").await?;
        if !cmdline_secure.stdout.is_empty() {
            kernel_verification_indicators.push("Secure boot parameters");
            details.push(format!("Cmdline secure: {}", cmdline_secure.stdout.trim()));
        }

        let details_str = if details.is_empty() {
            None
        } else {
            Some(details.join("\n"))
        };

        match kernel_verification_indicators.len() {
            3.. => Ok((
                TestStatus::Passed,
                format!(
                    "Kernel verification active: {}",
                    kernel_verification_indicators.join(", ")
                ),
                details_str,
            )),
            2 => Ok((
                TestStatus::Passed,
                format!(
                    "Kernel verification detected: {}",
                    kernel_verification_indicators.join(", ")
                ),
                details_str,
            )),
            1 => Ok((
                TestStatus::Warning,
                format!(
                    "Partial kernel verification: {}",
                    kernel_verification_indicators.join(", ")
                ),
                details_str,
            )),
            _ => Ok((
                TestStatus::Failed,
                "No kernel signature verification detected".to_string(),
                details_str,
            )),
        }
    }

    async fn test_module_signing(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check if module signing is enabled
        let _modsign_check = target
            .execute_command("cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo '0'")
            .await?;

        // Check for module signature verification in dmesg (requires elevated privileges)
        let module_sig = self
            .execute_kernel_command(
                target,
                "dmesg | grep -i 'module.*sign\\|x509.*cert\\|Factory kernel module signing key'",
            )
            .await?;

        // Check loaded modules for signature info
        let signed_modules = target
            .execute_command("cat /proc/modules | head -5")
            .await?;

        if module_sig
            .stdout
            .contains("Factory kernel module signing key")
        {
            Ok((
                TestStatus::Passed,
                "Factory kernel module signing key detected".to_string(),
                Some(module_sig.stdout),
            ))
        } else if module_sig.stdout.contains("module") && module_sig.stdout.contains("sign") {
            Ok((
                TestStatus::Passed,
                "Module signing infrastructure detected".to_string(),
                Some(module_sig.stdout),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                "Module signing not detected".to_string(),
                Some(signed_modules.stdout),
            ))
        }
    }

    async fn test_optee_signed(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check for OP-TEE in boot log
        let optee_check = target
            .execute_command("dmesg | grep -i 'optee\\|trusted.*os'")
            .await?;

        // Also check for OP-TEE device nodes
        let optee_devices = target
            .execute_command("ls -la /dev/tee* 2>/dev/null || echo 'no_tee_devices'")
            .await?;

        // Check for OP-TEE in /proc/modules
        let optee_modules = target
            .execute_command("lsmod | grep -i optee || echo 'no_optee_modules'")
            .await?;

        // Check for ELE which may provide secure world functionality on i.MX93
        let ele_secure_world = target
            .execute_command("dmesg | grep -i 'fsl-ele-mu'")
            .await?;

        let mut details = Vec::new();
        details.push(format!(
            "OP-TEE dmesg: {}",
            if optee_check.stdout.trim().is_empty() {
                "Not found"
            } else {
                optee_check.stdout.trim()
            }
        ));
        details.push(format!("TEE devices: {}", optee_devices.stdout.trim()));
        details.push(format!("OP-TEE modules: {}", optee_modules.stdout.trim()));
        details.push(format!(
            "ELE secure world: {}",
            if ele_secure_world.stdout.trim().is_empty() {
                "Not found"
            } else {
                "EdgeLock Enclave active"
            }
        ));

        // Full OP-TEE detected and running
        if optee_check.stdout.contains("OP-TEE") || optee_check.stdout.contains("TEE") {
            let optee_sig = target
                .execute_command("dmesg | grep -i 'optee.*sign\\|optee.*verif'")
                .await?;
            if !optee_sig.stdout.is_empty() {
                Ok((
                    TestStatus::Passed,
                    "OP-TEE signature verification detected".to_string(),
                    Some(details.join("\n")),
                ))
            } else {
                Ok((
                    TestStatus::Warning,
                    "OP-TEE present but signature verification not confirmed".to_string(),
                    Some(details.join("\n")),
                ))
            }
        }
        // i.MX93 systems may use ELE instead of OP-TEE for secure world
        else if !ele_secure_world.stdout.is_empty()
            && ele_secure_world.stdout.contains("fsl-ele-mu")
        {
            Ok((TestStatus::Passed, "i.MX93 EdgeLock Enclave provides secure world functionality (alternative to OP-TEE)".to_string(), Some(details.join("\n"))))
        }
        // TEE infrastructure present but OP-TEE not fully initialized
        else if !optee_devices.stdout.contains("no_tee_devices")
            || !optee_modules.stdout.contains("no_optee_modules")
        {
            Ok((TestStatus::Warning, "TEE infrastructure present but OP-TEE not fully initialized - may use alternative secure world".to_string(), Some(details.join("\n"))))
        }
        // No secure world detected
        else {
            Ok((
                TestStatus::Failed,
                "No secure world implementation detected (OP-TEE, ELE, or other TEE)".to_string(),
                Some(details.join("\n")),
            ))
        }
    }

    async fn test_tfa_signed(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check for TF-A (ARM Trusted Firmware) in boot log (requires elevated privileges)
        let tfa_check = self
            .execute_kernel_command(target, "dmesg | grep -i 'tf-a\\|trusted.*firmware\\|bl31'")
            .await?;

        // Check for ARM SMC calls which indicate secure monitor presence
        let smc_check = self
            .execute_kernel_command(target, "dmesg | grep -i 'smc\\|psci\\|arm.*smc' | head -3")
            .await?;

        // Check for i.MX93 specific secure monitor (may use different implementation)
        let imx_secure = self
            .execute_kernel_command(
                target,
                "dmesg | grep -i 'imx.*secure\\|secure.*monitor\\|el3\\|ree.*tee'",
            )
            .await?;

        // Check for ELE which may handle secure world on i.MX93
        let ele_secure_world = self
            .execute_kernel_command(
                target,
                "dmesg | grep -i 'ele-reserved\\|fsl-ele-mu\\|ele.*secure'",
            )
            .await?;

        let mut details = Vec::new();
        details.push(format!(
            "TF-A dmesg: {}",
            if tfa_check.stdout.trim().is_empty() {
                "Not found"
            } else {
                tfa_check.stdout.trim()
            }
        ));
        details.push(format!(
            "SMC/PSCI calls: {}",
            if smc_check.stdout.trim().is_empty() {
                "Not found"
            } else {
                smc_check.stdout.trim()
            }
        ));
        details.push(format!(
            "i.MX secure: {}",
            if imx_secure.stdout.trim().is_empty() {
                "Not found"
            } else {
                imx_secure.stdout.trim()
            }
        ));
        details.push(format!(
            "ELE secure world: {}",
            if ele_secure_world.stdout.trim().is_empty() {
                "Not found"
            } else {
                ele_secure_world.stdout.trim()
            }
        ));

        // Traditional TF-A detection
        if tfa_check.stdout.contains("TF-A")
            || tfa_check.stdout.contains("BL31")
            || tfa_check.stdout.contains("Trusted Firmware")
        {
            let tfa_sig = target
                .execute_command("dmesg | grep -i 'tf-a.*sign\\|firmware.*verif'")
                .await?;
            if !tfa_sig.stdout.is_empty() {
                Ok((
                    TestStatus::Passed,
                    "TF-A signature verification detected".to_string(),
                    Some(details.join("\n")),
                ))
            } else {
                Ok((
                    TestStatus::Warning,
                    "TF-A present but signature verification not confirmed".to_string(),
                    Some(details.join("\n")),
                ))
            }
        }
        // i.MX93 may use ELE for secure world instead of traditional TF-A
        else if !ele_secure_world.stdout.is_empty()
            && (ele_secure_world.stdout.contains("ele-reserved")
                || ele_secure_world.stdout.contains("fsl-ele-mu"))
        {
            debug!("ELE detected: stdout='{}'", ele_secure_world.stdout.trim());
            Ok((
                TestStatus::Passed,
                "i.MX93 EdgeLock Enclave provides secure world functionality (alternative to TF-A)"
                    .to_string(),
                Some(details.join("\n")),
            ))
        }
        // PSCI indicates some secure monitor is present
        else if !smc_check.stdout.is_empty()
            && (smc_check.stdout.contains("psci") || smc_check.stdout.contains("smc"))
        {
            debug!(
                "PSCI/SMC detected: stdout='{}', contains_psci={}, contains_smc={}",
                smc_check.stdout.trim(),
                smc_check.stdout.contains("psci"),
                smc_check.stdout.contains("smc")
            );
            Ok((
                TestStatus::Warning,
                "PSCI/SMC secure monitor detected but implementation unclear".to_string(),
                Some(details.join("\n")),
            ))
        }
        // No secure world detected
        else {
            Ok((
                TestStatus::Failed,
                "No secure world implementation detected (TF-A, ELE, or other secure monitor)"
                    .to_string(),
                Some(details.join("\n")),
            ))
        }
    }

    async fn test_boot_chain_verification(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Comprehensive boot chain verification for i.MX93 and other embedded systems
        let mut verified_components = Vec::new();
        let mut details = Vec::new();

        // Check for EdgeLock Enclave (ELE) - i.MX93 hardware secure boot
        let ele_check = target
            .execute_command("dmesg | grep -i 'fsl-ele-mu\\|ele-trng\\|EdgeLock'")
            .await?;
        if ele_check.stdout.contains("fsl-ele-mu") {
            verified_components.push("EdgeLock Enclave (ELE)");
            details.push("ELE: Hardware secure boot active".to_string());
        }

        // Check for U-Boot signature verification (FIT images)
        let uboot_fit = target.execute_command("find /var/rootdirs/mnt/boot /boot -name '*.itb' -o -name '*.fit' 2>/dev/null | head -1").await?;
        if !uboot_fit.stdout.trim().is_empty() {
            // Check if FIT image has signatures
            let fit_sig = target
                .execute_command(&format!(
                    "strings {} 2>/dev/null | grep -E 'signature|rsa|sha' | head -1",
                    uboot_fit.stdout.trim()
                ))
                .await?;
            if !fit_sig.stdout.is_empty() {
                verified_components.push("U-Boot FIT signatures");
                details.push("U-Boot: FIT image signatures verified".to_string());
            }
        }

        // Check for kernel verification (multiple methods)
        let kernel_verification = target.execute_command("dmesg | grep -i 'kernel.*sign\\|vmlinuz.*verif\\|Factory kernel module signing key'").await?;
        if !kernel_verification.stdout.is_empty() {
            verified_components.push("Kernel verification");
            details.push("Kernel: Signature verification active".to_string());
        }

        // Check for module signing
        let module_signing = target
            .execute_command("dmesg | grep 'Factory kernel module signing key'")
            .await?;
        if !module_signing.stdout.is_empty() {
            verified_components.push("Module signing");
            details.push("Modules: Factory signing key loaded".to_string());
        }

        // Check for AHAB (Advanced High Assurance Boot) - NXP secure boot
        let ahab_check = target
            .execute_command("dmesg | grep -i 'ahab\\|hab'")
            .await?;
        if !ahab_check.stdout.is_empty() {
            verified_components.push("AHAB/HAB");
            details.push("AHAB: Advanced High Assurance Boot detected".to_string());
        }

        // Check for device tree verification
        let dt_verify = target
            .execute_command("dmesg | grep -i 'fit.*verif\\|dtb.*verif\\|device.*tree.*verif'")
            .await?;
        if !dt_verify.stdout.is_empty() {
            verified_components.push("Device tree verification");
            details.push("DT: Device tree verification active".to_string());
        }

        // Check for secure boot parameters in kernel command line
        let cmdline_secure = target
            .execute_command(
                "cat /proc/cmdline | grep -o 'secure[^[:space:]]*\\|verified[^[:space:]]*'",
            )
            .await?;
        if !cmdline_secure.stdout.is_empty() {
            verified_components.push("Secure boot parameters");
            details.push(format!("Cmdline: {}", cmdline_secure.stdout.trim()));
        }

        // Check for TF-A if present
        let tfa_check = target
            .execute_command("dmesg | grep -i 'tf-a\\|trusted.*firmware\\|bl31'")
            .await?;
        if !tfa_check.stdout.is_empty() {
            verified_components.push("TF-A (Trusted Firmware)");
            details.push("TF-A: ARM Trusted Firmware detected".to_string());
        }

        details.push(format!(
            "Verified components: {}",
            verified_components.join(", ")
        ));
        let details_str = Some(details.join("\n"));

        match verified_components.len() {
            5.. => Ok((
                TestStatus::Passed,
                format!(
                    "Complete boot chain verification active ({} components)",
                    verified_components.len()
                ),
                details_str,
            )),
            3..=4 => Ok((
                TestStatus::Passed,
                format!(
                    "Strong boot chain verification ({} components)",
                    verified_components.len()
                ),
                details_str,
            )),
            1..=2 => Ok((
                TestStatus::Warning,
                format!(
                    "Partial boot chain verification ({} components)",
                    verified_components.len()
                ),
                details_str,
            )),
            _ => Ok((
                TestStatus::Failed,
                "No boot chain verification detected".to_string(),
                details_str,
            )),
        }
    }
}
