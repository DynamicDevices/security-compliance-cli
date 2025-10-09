use crate::{
    error::Result,
    target::Target,
    tests::{create_test_result, SecurityTest, TestResult, TestStatus},
};
use async_trait::async_trait;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum RuntimeSecurityTests {
    FilesystemEncryption,
    FirewallActive,
    SelinuxStatus,
    SshConfiguration,
    UserPermissions,
    ServiceHardening,
    KernelProtections,
    ReadOnlyFilesystem,
    FoundriesLmpSecurity,
}

#[async_trait]
impl SecurityTest for RuntimeSecurityTests {
    async fn run(&self, target: &mut Target) -> Result<TestResult> {
        let start_time = Instant::now();

        let result = match self {
            Self::FilesystemEncryption => self.test_filesystem_encryption(target).await,
            Self::FirewallActive => self.test_firewall_active(target).await,
            Self::SelinuxStatus => self.test_selinux_status(target).await,
            Self::SshConfiguration => self.test_ssh_configuration(target).await,
            Self::UserPermissions => self.test_user_permissions(target).await,
            Self::ServiceHardening => self.test_service_hardening(target).await,
            Self::KernelProtections => self.test_kernel_protections(target).await,
            Self::ReadOnlyFilesystem => self.test_readonly_filesystem(target).await,
            Self::FoundriesLmpSecurity => self.test_foundries_lmp_security(target).await,
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
            Self::FilesystemEncryption => "runtime_001",
            Self::FirewallActive => "runtime_002",
            Self::SelinuxStatus => "runtime_003",
            Self::SshConfiguration => "runtime_004",
            Self::UserPermissions => "runtime_005",
            Self::ServiceHardening => "runtime_006",
            Self::KernelProtections => "runtime_007",
            Self::ReadOnlyFilesystem => "runtime_008",
            Self::FoundriesLmpSecurity => "runtime_009",
        }
    }

    fn test_name(&self) -> &str {
        match self {
            Self::FilesystemEncryption => "Filesystem Encryption (LUKS)",
            Self::FirewallActive => "Firewall Configuration",
            Self::SelinuxStatus => "SELinux Status",
            Self::SshConfiguration => "SSH Security Configuration",
            Self::UserPermissions => "User Permission Security",
            Self::ServiceHardening => "Service Hardening",
            Self::KernelProtections => "Kernel Security Protections",
            Self::ReadOnlyFilesystem => "Read-Only Filesystem Protection",
            Self::FoundriesLmpSecurity => "Foundries.io LMP Security Features",
        }
    }

    fn category(&self) -> &str {
        "runtime"
    }

    fn description(&self) -> &str {
        match self {
            Self::FilesystemEncryption => "Validates that sensitive data is protected at rest through full disk encryption using LUKS (Linux Unified Key Setup). Checks for encrypted root filesystem and proper key management. Essential for protecting data confidentiality if the device is physically compromised or stolen.",
            Self::FirewallActive => "Ensures network traffic filtering is active through iptables/netfilter firewall rules. Validates that only authorized network connections are permitted and malicious traffic is blocked. Critical for preventing network-based attacks and unauthorized access attempts.",
            Self::SelinuxStatus => "Verifies SELinux (Security-Enhanced Linux) mandatory access control framework is active and properly configured. SELinux provides fine-grained security policies that limit process capabilities and prevent privilege escalation attacks, even if applications are compromised.",
            Self::SshConfiguration => "Evaluates SSH daemon security configuration including authentication methods, encryption protocols, and access controls. Checks for secure key exchange, disabled password authentication, and proper user restrictions. Fundamental for secure remote administration and preventing SSH-based attacks.",
            Self::UserPermissions => "Analyzes user account security including privilege separation, sudo configuration, and account policies. Ensures principle of least privilege is enforced and prevents unauthorized privilege escalation. Critical for maintaining system integrity and preventing insider threats.",
            Self::ServiceHardening => "Assesses system service security hardening including service isolation, capability restrictions, and secure service configurations. Verifies services run with minimal privileges and proper security boundaries. Important for reducing attack surface and containing potential compromises.",
            Self::KernelProtections => "Validates kernel-level security features including ASLR (Address Space Layout Randomization), stack protection, and other exploit mitigation techniques. These protections make it significantly harder for attackers to exploit memory corruption vulnerabilities and achieve code execution.",
            Self::ReadOnlyFilesystem => "Validates that critical system directories are mounted read-only to prevent unauthorized modifications and enhance system integrity. Checks Foundries.io LMP read-only root filesystem configuration with proper writable areas for logs, data, and temporary files. Essential for preventing persistent attacks and maintaining system consistency.",
            Self::FoundriesLmpSecurity => "Comprehensive evaluation of Foundries.io Linux Micro Platform (LMP) specific security features including OSTree immutable filesystem, aktualizr-lite OTA updates, Docker security, and platform-specific hardening. Validates that LMP security architecture is properly configured for embedded IoT deployment security.",
        }
    }
}

impl RuntimeSecurityTests {
    async fn test_filesystem_encryption(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check for LUKS encrypted devices
        let luks_check = target.execute_command("lsblk -f | grep -i luks").await?;

        // Check for dm-crypt devices
        let dmcrypt_check = target
            .execute_command("ls -la /dev/mapper/ | grep -v control")
            .await?;

        // Check if cryptsetup is available
        let cryptsetup = target.execute_command("which cryptsetup").await?;

        // Check mount points for encrypted filesystems
        let mount_check = target
            .execute_command("mount | grep -E 'crypt|luks|mapper'")
            .await?;

        let mut details = Vec::new();
        details.push(format!("LUKS devices: {}", luks_check.stdout));
        details.push(format!("Device mapper: {}", dmcrypt_check.stdout));
        details.push(format!("Encrypted mounts: {}", mount_check.stdout));

        if luks_check.stdout.contains("crypto_LUKS") || mount_check.stdout.contains("mapper") {
            Ok((
                TestStatus::Passed,
                "LUKS filesystem encryption detected".to_string(),
                Some(details.join("\n")),
            ))
        } else if dmcrypt_check.stdout.lines().count() > 1 {
            // More than just 'control' device exists
            Ok((
                TestStatus::Warning,
                "Device mapper present but LUKS not confirmed".to_string(),
                Some(details.join("\n")),
            ))
        } else if cryptsetup.exit_code == 0 {
            Ok((
                TestStatus::Warning,
                "Cryptsetup available but no encrypted filesystems detected".to_string(),
                Some(details.join("\n")),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                "No filesystem encryption detected".to_string(),
                Some(details.join("\n")),
            ))
        }
    }

    async fn test_firewall_active(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check iptables rules - try direct access first, then sudo if needed
        let iptables = target.execute_command("iptables -L -n").await?;
        let mut iptables_result = iptables.clone();
        let mut used_sudo = false;

        if iptables.exit_code != 0 {
            // Try with sudo if direct access failed
            // Use echo to pass the password to sudo via stdin (-S option)
            let sudo_command = format!("echo '{}' | sudo -S iptables -L -n", target.get_password());
            iptables_result = target.execute_command(&sudo_command).await?;
            used_sudo = true;
        }

        // Check if iptables service is running
        let _iptables_service = target
            .execute_command("systemctl is-active iptables 2>/dev/null || echo 'not_running'")
            .await?;

        // Check for netfilter modules
        let netfilter_modules = target
            .execute_command("lsmod | grep -E 'iptable|netfilter|nf_'")
            .await?;

        // Check if iptables binary is available
        let iptables_available = target.execute_command("which iptables").await?;

        let mut details = Vec::new();
        details.push(format!("iptables rules:\n{}", iptables_result.stdout));
        details.push(format!("Netfilter modules: {}", netfilter_modules.stdout));
        details.push(format!(
            "iptables binary available: {}",
            iptables_available.exit_code == 0
        ));
        if used_sudo {
            details.push("Used sudo to access iptables rules".to_string());
        }

        // Check if we have any firewall rules configured
        if iptables_result.exit_code == 0
            && !iptables_result
                .stdout
                .contains("Chain INPUT (policy ACCEPT)")
        {
            Ok((
                TestStatus::Passed,
                "Firewall rules configured".to_string(),
                Some(details.join("\n")),
            ))
        } else if iptables_result.exit_code == 0
            && iptables_result
                .stdout
                .contains("Chain INPUT (policy ACCEPT)")
        {
            // iptables is available but using default ACCEPT policy
            let rule_count = iptables_result
                .stdout
                .lines()
                .filter(|line| {
                    line.contains("ACCEPT") || line.contains("DROP") || line.contains("REJECT")
                })
                .count();

            if rule_count > 3 {
                // More than just the default chains
                Ok((
                    TestStatus::Warning,
                    "iptables available with some rules but default ACCEPT policy".to_string(),
                    Some(details.join("\n")),
                ))
            } else {
                // Default configuration - treat as warning in pre-production, but note that iptables is present
                Ok((
                    TestStatus::Warning,
                    "iptables present but firewall not configured (default ACCEPT policy)"
                        .to_string(),
                    Some(details.join("\n")),
                ))
            }
        } else if iptables_available.exit_code == 0 {
            // iptables binary exists but both direct and sudo commands failed
            if iptables_result.stderr.contains("Permission denied")
                || iptables_result.stderr.contains("Operation not permitted")
            {
                Ok((
                    TestStatus::Warning,
                    "iptables available but access denied".to_string(),
                    Some(details.join("\n")),
                ))
            } else {
                Ok((
                    TestStatus::Warning,
                    "iptables available but unable to read rules".to_string(),
                    Some(details.join("\n")),
                ))
            }
        } else {
            // No iptables at all - warning for pre-production environments
            Ok((
                TestStatus::Warning,
                "No firewall configuration detected (iptables not available)".to_string(),
                Some(details.join("\n")),
            ))
        }
    }

    async fn test_selinux_status(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check SELinux status
        let selinux_status = target
            .execute_command("getenforce 2>/dev/null || echo 'not_available'")
            .await?;

        // Check SELinux config
        let selinux_config = target
            .execute_command("cat /etc/selinux/config 2>/dev/null || echo 'not_found'")
            .await?;

        // Check if SELinux filesystem is mounted
        let _selinux_fs = target.execute_command("mount | grep selinux").await?;

        // Check for alternative LSM modules
        let lsm_modules = target
            .execute_command("cat /sys/kernel/security/lsm 2>/dev/null || echo 'lsm_not_available'")
            .await?;

        let mut details = Vec::new();
        details.push(format!("SELinux status: {}", selinux_status.stdout.trim()));
        details.push(format!("SELinux config: {}", selinux_config.stdout));
        details.push(format!("Active LSM modules: {}", lsm_modules.stdout.trim()));

        match selinux_status.stdout.trim() {
            "Enforcing" => Ok((
                TestStatus::Passed,
                "SELinux is enforcing".to_string(),
                Some(details.join("\n")),
            )),
            "Permissive" => Ok((
                TestStatus::Warning,
                "SELinux is permissive (not enforcing)".to_string(),
                Some(details.join("\n")),
            )),
            "Disabled" => Ok((
                TestStatus::Failed,
                "SELinux is disabled - security policy not enforced".to_string(),
                Some(details.join("\n")),
            )),
            "not_available" => {
                // Check for alternative security modules
                if !lsm_modules.stdout.contains("lsm_not_available") {
                    let active_lsms = lsm_modules.stdout.trim();
                    if active_lsms.contains("landlock")
                        || active_lsms.contains("apparmor")
                        || active_lsms.contains("smack")
                        || active_lsms.contains("tomoyo")
                    {
                        Ok((
                            TestStatus::Passed,
                            format!("Alternative LSM security active: {}", active_lsms),
                            Some(details.join("\n")),
                        ))
                    } else if active_lsms.contains("capability") {
                        Ok((
                            TestStatus::Warning,
                            format!("Basic LSM security active: {}", active_lsms),
                            Some(details.join("\n")),
                        ))
                    } else {
                        Ok((
                            TestStatus::Failed,
                            "No mandatory access control system detected".to_string(),
                            Some(details.join("\n")),
                        ))
                    }
                } else {
                    Ok((
                        TestStatus::Failed,
                        "SELinux not available and cannot check alternative LSM modules"
                            .to_string(),
                        None,
                    ))
                }
            }
            _ => Ok((
                TestStatus::Warning,
                "SELinux status unknown".to_string(),
                Some(details.join("\n")),
            )),
        }
    }

    async fn test_ssh_configuration(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check SSH configuration
        let ssh_config = target.execute_command("cat /etc/ssh/sshd_config | grep -E '^[^#]*(PermitRootLogin|PasswordAuthentication|Protocol|Port|Ciphers|MACs|KexAlgorithms|PubkeyAcceptedKeyTypes|HostKeyAlgorithms)'").await?;

        // Check SSH service status
        let _ssh_status = target.execute_command("systemctl is-active ssh 2>/dev/null || systemctl is-active sshd 2>/dev/null || echo 'not_running'").await?;

        // Get SSH daemon's supported algorithms
        let ssh_algorithms = target.execute_command("sshd -T 2>/dev/null | grep -E '^(ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedkeytypes)' || echo 'algorithms_not_available'").await?;

        let mut security_issues = Vec::new();
        let mut security_good = Vec::new();
        let mut critical_issues = Vec::new();
        let mut algorithm_issues = Vec::new();

        // Check for critical security issues (always errors)
        if ssh_config.stdout.contains("PermitRootLogin yes") {
            security_issues.push("Root login permitted");
            critical_issues
                .push("Root login permitted - this is a critical security vulnerability");
        } else if ssh_config.stdout.contains("PermitRootLogin no") {
            security_good.push("Root login disabled");
        }

        // Check for other security issues (warnings)
        if ssh_config.stdout.contains("PasswordAuthentication yes") {
            security_issues.push("Password authentication enabled");

            // If password auth is enabled, check for default credentials risk
            let current_user = target.execute_command("whoami").await?;
            if current_user.stdout.trim() == "fio" {
                // Check if this might be using default credentials
                let ssh_key_check = target
                    .execute_command("ls -la ~/.ssh/authorized_keys 2>/dev/null || echo 'no_keys'")
                    .await?;
                let home_setup_check = target
                    .execute_command("ls -la ~/.bashrc ~/.profile 2>/dev/null | wc -l")
                    .await?;

                if ssh_key_check.stdout.contains("no_keys")
                    && home_setup_check.stdout.trim().parse::<i32>().unwrap_or(0) <= 1
                {
                    critical_issues.push("Password authentication enabled with potentially default 'fio' user credentials");
                    security_issues
                        .push("Default user with password auth (critical security risk)");
                } else {
                    security_issues.push("Password authentication enabled with default user (verify credentials changed)");
                }
            }
        } else if ssh_config.stdout.contains("PasswordAuthentication no") {
            security_good.push("Password authentication disabled");
        } else {
            // If not explicitly configured, check what the default is
            if ssh_algorithms.stdout.contains("password")
                || !ssh_algorithms.stdout.contains("algorithms_not_available")
            {
                security_issues
                    .push("Password authentication status unclear (may be enabled by default)");
            }
        }

        // Check SSH protocol version
        if ssh_config.stdout.contains("Protocol 1") {
            critical_issues.push("SSH Protocol 1 enabled - extremely insecure");
            security_issues.push("SSH Protocol 1 enabled");
        } else {
            security_good.push("SSH Protocol 2 (secure)");
        }

        // Check for weak/insecure algorithms
        if !ssh_algorithms.stdout.contains("algorithms_not_available") {
            // Check ciphers for weak algorithms
            if ssh_algorithms.stdout.contains("3des-cbc")
                || ssh_algorithms.stdout.contains("aes128-cbc")
                || ssh_algorithms.stdout.contains("aes192-cbc")
                || ssh_algorithms.stdout.contains("aes256-cbc")
                || ssh_algorithms.stdout.contains("blowfish-cbc")
                || ssh_algorithms.stdout.contains("cast128-cbc")
                || ssh_algorithms.stdout.contains("arcfour")
            {
                algorithm_issues.push("Weak ciphers enabled (CBC mode or weak algorithms)");
                security_issues.push("Weak ciphers enabled");
            }

            // Check MACs for weak algorithms
            if ssh_algorithms.stdout.contains("hmac-md5")
                || ssh_algorithms.stdout.contains("hmac-sha1-96")
                || ssh_algorithms.stdout.contains("hmac-md5-96")
            {
                algorithm_issues.push("Weak MAC algorithms enabled (MD5 or truncated SHA1)");
                security_issues.push("Weak MAC algorithms");
            }

            // Check Key Exchange algorithms
            if ssh_algorithms.stdout.contains("diffie-hellman-group1-sha1")
                || ssh_algorithms
                    .stdout
                    .contains("diffie-hellman-group14-sha1")
                || ssh_algorithms
                    .stdout
                    .contains("diffie-hellman-group-exchange-sha1")
            {
                algorithm_issues.push("Weak key exchange algorithms enabled (SHA1-based)");
                security_issues.push("Weak key exchange algorithms");
            }

            // Check for good algorithms
            if ssh_algorithms
                .stdout
                .contains("chacha20-poly1305@openssh.com")
                || ssh_algorithms.stdout.contains("aes256-gcm@openssh.com")
                || ssh_algorithms.stdout.contains("aes128-gcm@openssh.com")
            {
                security_good.push("Strong ciphers available");
            }

            if ssh_algorithms.stdout.contains("umac-128-etm@openssh.com")
                || ssh_algorithms
                    .stdout
                    .contains("hmac-sha2-256-etm@openssh.com")
                || ssh_algorithms
                    .stdout
                    .contains("hmac-sha2-512-etm@openssh.com")
            {
                security_good.push("Strong MAC algorithms available");
            }

            if ssh_algorithms.stdout.contains("curve25519-sha256")
                || ssh_algorithms.stdout.contains("ecdh-sha2-nistp256")
                || ssh_algorithms
                    .stdout
                    .contains("diffie-hellman-group16-sha512")
            {
                security_good.push("Strong key exchange algorithms available");
            }
        } else {
            security_issues.push("Unable to verify SSH algorithm configuration");
        }

        let mut details_parts = vec![
            format!("SSH Config:\n{}", ssh_config.stdout),
            format!("Good: {:?}", security_good),
            format!("Issues: {:?}", security_issues),
        ];

        if !algorithm_issues.is_empty() {
            details_parts.push(format!("Algorithm Issues: {:?}", algorithm_issues));
        }

        if !ssh_algorithms.stdout.contains("algorithms_not_available") {
            details_parts.push(format!("SSH Algorithms:\n{}", ssh_algorithms.stdout));
        }

        let details = details_parts.join("\n");

        // Critical issues (like root login or Protocol 1) always result in failure
        if !critical_issues.is_empty() {
            Ok((
                TestStatus::Failed,
                format!(
                    "SSH critical security issues: {}",
                    critical_issues.join(", ")
                ),
                Some(details),
            ))
        } else if security_issues.is_empty() && !security_good.is_empty() {
            Ok((
                TestStatus::Passed,
                "SSH configuration secure".to_string(),
                Some(details),
            ))
        } else if security_issues.len() <= 2 {
            Ok((
                TestStatus::Warning,
                format!("SSH has {} security issues", security_issues.len()),
                Some(details),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                format!("SSH has {} security issues", security_issues.len()),
                Some(details),
            ))
        }
    }

    async fn test_user_permissions(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check for users with UID 0 (root privileges)
        let root_users = target
            .execute_command("awk -F: '$3 == 0 { print $1 }' /etc/passwd")
            .await?;

        // Also check if root user exists directly
        let root_exists = target
            .execute_command("id root 2>/dev/null || echo 'not_found'")
            .await?;

        // Check if root login is disabled
        let root_passwd_entry = target.execute_command("grep '^root:' /etc/passwd").await?;
        let root_shadow_entry = target
            .execute_command(
                "grep '^root:' /etc/shadow 2>/dev/null || echo 'shadow_not_accessible'",
            )
            .await?;

        // Check sudo configuration
        let sudo_config = target
            .execute_command("cat /etc/sudoers.d/* 2>/dev/null | grep -v '^#' | head -10")
            .await?;

        // Check for users with shell access
        let shell_users = target
            .execute_command("grep -E '/bin/(bash|sh|zsh)$' /etc/passwd | wc -l")
            .await?;

        // Check current user info
        let current_user = target.execute_command("whoami").await?;
        let current_user_groups = target.execute_command("groups").await?;

        let mut details = Vec::new();
        let mut security_issues = Vec::new();

        // Check for default credentials (fio:fio) - this is a critical security check
        let using_default_creds = current_user.stdout.trim() == "fio";
        let mut default_creds_risk = false;

        if using_default_creds {
            // Try to verify if default password is still in use
            // We can't directly test the password, but we can check if it's likely default
            let _fio_passwd_entry = target.execute_command("grep '^fio:' /etc/passwd").await?;
            let fio_shadow_entry = target
                .execute_command(
                    "grep '^fio:' /etc/shadow 2>/dev/null || echo 'shadow_not_accessible'",
                )
                .await?;

            // Check if password might be default by looking at shadow file
            if !fio_shadow_entry.stdout.contains("shadow_not_accessible")
                && !fio_shadow_entry.stdout.trim().is_empty()
            {
                let shadow_fields: Vec<&str> = fio_shadow_entry.stdout.trim().split(':').collect();
                if shadow_fields.len() >= 2 {
                    let password_hash = shadow_fields[1];
                    // Check for common default password hashes or patterns that suggest default password
                    // Note: We can't directly verify the password, but we can check for suspicious patterns
                    if password_hash.len() < 20 || password_hash.starts_with("$1$") {
                        // Short hash or old MD5 hash might indicate weak/default password
                        default_creds_risk = true;
                        details.push(
                            "WARNING: fio user may be using default or weak password".to_string(),
                        );
                    }
                }
            }

            // Additional checks for default setup indicators
            let home_dir_check = target
                .execute_command("ls -la /home/fio/.bashrc /home/fio/.profile 2>/dev/null | wc -l")
                .await?;
            let ssh_key_check = target
                .execute_command(
                    "ls -la /home/fio/.ssh/authorized_keys 2>/dev/null || echo 'no_keys'",
                )
                .await?;

            if home_dir_check.stdout.trim().parse::<i32>().unwrap_or(0) <= 1
                && ssh_key_check.stdout.contains("no_keys")
            {
                // Minimal home directory setup + no SSH keys suggests default installation
                default_creds_risk = true;
                details.push(
                    "WARNING: fio user appears to have default installation setup".to_string(),
                );
                security_issues.push(
                    "Default user 'fio' detected with potentially default credentials".to_string(),
                );
            }
        }

        details.push(format!(
            "Root users (UID 0): {}",
            if root_users.stdout.trim().is_empty() {
                "none detected"
            } else {
                &root_users.stdout
            }
        ));
        details.push(format!(
            "Root user exists: {}",
            if root_exists.stdout.contains("not_found") {
                "no"
            } else {
                "yes"
            }
        ));
        details.push(format!("Shell users count: {}", shell_users.stdout.trim()));
        // Add default credentials information to details
        if using_default_creds {
            details.push(format!(
                "Current user: {} (default Foundries.io user)",
                current_user.stdout.trim()
            ));
            if default_creds_risk {
                details.push(
                    "⚠️  WARNING: Using default 'fio' user with potentially default credentials"
                        .to_string(),
                );
            } else {
                details.push("Using 'fio' user (appears to be customized)".to_string());
            }
        } else {
            details.push(format!("Current user: {}", current_user.stdout.trim()));
        }
        details.push(format!(
            "Current user groups: {}",
            current_user_groups.stdout.trim()
        ));

        // Analyze root login status
        let mut root_login_disabled = false;
        if !root_passwd_entry.stdout.trim().is_empty() {
            let passwd_fields: Vec<&str> = root_passwd_entry.stdout.trim().split(':').collect();
            if passwd_fields.len() >= 7 {
                let shell = passwd_fields[6];
                let password_field = passwd_fields[1];

                // Check if root has a disabled shell
                if shell.contains("/nologin")
                    || shell.contains("/false")
                    || shell.contains("/bin/false")
                {
                    root_login_disabled = true;
                    details.push(format!("Root shell: {} (login disabled)", shell));
                } else {
                    details.push(format!("Root shell: {} (login possible)", shell));
                    security_issues.push("Root user has login shell enabled".to_string());
                }

                // Check password field
                if password_field == "x" {
                    details.push("Root password: managed by shadow file".to_string());

                    // Check shadow file if accessible
                    if !root_shadow_entry.stdout.contains("shadow_not_accessible")
                        && !root_shadow_entry.stdout.trim().is_empty()
                    {
                        let shadow_fields: Vec<&str> =
                            root_shadow_entry.stdout.trim().split(':').collect();
                        if shadow_fields.len() >= 2 {
                            let password_hash = shadow_fields[1];
                            if password_hash == "!"
                                || password_hash == "*"
                                || password_hash.starts_with("!")
                            {
                                details.push("Root password: locked/disabled".to_string());
                                if !root_login_disabled {
                                    root_login_disabled = true; // Password locked counts as login disabled
                                }
                            } else if !password_hash.is_empty() {
                                details.push("Root password: set (hash present)".to_string());
                                if !root_login_disabled {
                                    security_issues.push(
                                        "Root user password is set and login shell is available"
                                            .to_string(),
                                    );
                                }
                            } else {
                                details.push("Root password: empty (no password)".to_string());
                                if !root_login_disabled {
                                    security_issues.push(
                                        "Root user has no password and login shell is available"
                                            .to_string(),
                                    );
                                }
                            }
                        }
                    } else {
                        details.push(
                            "Root password: shadow file not accessible for verification"
                                .to_string(),
                        );
                    }
                } else if password_field == "!" || password_field == "*" {
                    details.push("Root password: locked in passwd file".to_string());
                    if !root_login_disabled {
                        root_login_disabled = true;
                    }
                } else {
                    details.push("Root password: set in passwd file (legacy)".to_string());
                    if !root_login_disabled {
                        security_issues.push(
                            "Root user has password set in passwd file and login shell available"
                                .to_string(),
                        );
                    }
                }
            }
        } else {
            // Root user not found in passwd file - this could be good or bad
            if !root_exists.stdout.contains("not_found") {
                // Root user exists but not in passwd - might be managed differently
                details.push(
                    "Root user: exists but not in passwd file (possibly managed by system)"
                        .to_string(),
                );
                // Check if we can determine login status another way
                let passwd_root_check = target.execute_command("getent passwd root").await?;
                if !passwd_root_check.stdout.trim().is_empty() {
                    let passwd_fields: Vec<&str> =
                        passwd_root_check.stdout.trim().split(':').collect();
                    if passwd_fields.len() >= 7 {
                        let shell = passwd_fields[6];
                        if shell.contains("/nologin")
                            || shell.contains("/false")
                            || shell.contains("/bin/false")
                        {
                            root_login_disabled = true;
                            details.push(format!(
                                "Root shell (via getent): {} (login disabled)",
                                shell
                            ));
                        } else {
                            details.push(format!(
                                "Root shell (via getent): {} (login possible)",
                                shell
                            ));
                            security_issues.push("Root user has login shell enabled".to_string());
                        }
                    }
                } else {
                    details.push("Root user: cannot determine login status".to_string());
                }
            } else {
                details.push("Root user: not found in passwd file".to_string());
            }
        }

        if !sudo_config.stdout.trim().is_empty() {
            details.push(format!("Sudo config: {}", sudo_config.stdout));
        } else {
            details.push("Sudo config: no custom sudoers files found".to_string());
        }

        let root_count = if root_users.stdout.trim().is_empty() {
            // If awk didn't find UID 0 users, check if root exists another way
            if !root_exists.stdout.contains("not_found") {
                1
            } else {
                0
            }
        } else {
            root_users
                .stdout
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count()
        };

        let shell_count: usize = shell_users.stdout.trim().parse().unwrap_or(0);

        // Determine overall status based on root login and user counts
        if !security_issues.is_empty() {
            Ok((
                TestStatus::Failed,
                format!(
                    "User permission security issues: {}",
                    security_issues.join(", ")
                ),
                Some(details.join("\n")),
            ))
        } else if root_login_disabled && shell_count <= 3 {
            // Root login is properly disabled and reasonable number of shell users
            Ok((
                TestStatus::Passed,
                "User permissions secure (root login disabled)".to_string(),
                Some(details.join("\n")),
            ))
        } else if (root_count == 1 || root_login_disabled) && shell_count <= 3 {
            // Either normal root setup or root login disabled, with reasonable shell users
            Ok((
                TestStatus::Passed,
                "User permissions appear secure".to_string(),
                Some(details.join("\n")),
            ))
        } else if root_count <= 2 && shell_count <= 5 {
            Ok((
                TestStatus::Warning,
                "User permissions need review".to_string(),
                Some(details.join("\n")),
            ))
        } else if root_count == 0 && !root_login_disabled {
            // No root user detected and we couldn't verify it's disabled - this might be a detection issue
            Ok((
                TestStatus::Warning,
                "Unable to verify root user configuration".to_string(),
                Some(details.join("\n")),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                "Too many privileged users detected".to_string(),
                Some(details.join("\n")),
            ))
        }
    }

    async fn test_service_hardening(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check running services
        let services = target
            .execute_command(
                "systemctl list-units --type=service --state=running --no-pager | grep -v '@'",
            )
            .await?;

        // Check for unnecessary services
        let potentially_risky = ["telnet", "ftp", "rsh", "rlogin", "tftp"];
        let mut risky_services = Vec::new();

        for service in &potentially_risky {
            if services.stdout.contains(service) {
                risky_services.push(*service);
            }
        }

        // Count total running services
        let service_count = services
            .stdout
            .lines()
            .filter(|line| line.contains(".service"))
            .count();

        let details = format!(
            "Running services: {}\nRisky services: {:?}",
            service_count, risky_services
        );

        if risky_services.is_empty() && service_count <= 20 {
            Ok((
                TestStatus::Passed,
                "Service hardening looks good".to_string(),
                Some(details),
            ))
        } else if risky_services.is_empty() {
            Ok((
                TestStatus::Warning,
                format!("Many services running ({})", service_count),
                Some(details),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                format!("Risky services detected: {:?}", risky_services),
                Some(details),
            ))
        }
    }

    async fn test_kernel_protections(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        // Check kernel protection features
        let mut protections = Vec::new();
        let mut details = Vec::new();
        let mut recommendations = Vec::new();

        // Check ASLR
        let aslr = target
            .execute_command("cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo '0'")
            .await?;
        if aslr.stdout.trim() == "2" {
            protections.push("ASLR (full randomization)");
        } else if aslr.stdout.trim() == "1" {
            protections.push("ASLR (partial)");
            recommendations.push("Enable full ASLR: echo 2 > /proc/sys/kernel/randomize_va_space");
        } else {
            recommendations.push("Enable ASLR: echo 2 > /proc/sys/kernel/randomize_va_space");
        }
        details.push(format!("ASLR (randomize_va_space): {}", aslr.stdout.trim()));

        // Check DEP/NX bit - different approach for ARM64
        let arch = target.execute_command("uname -m").await?;
        if arch.stdout.trim() == "aarch64" {
            // ARM64 has Execute Never (XN) by default, check if PAN is available
            let pan_check = target
                .execute_command("grep -i 'pan' /proc/cpuinfo || echo 'not_found'")
                .await?;
            if pan_check.stdout.contains("pan") {
                protections.push("ARM64 PAN (Privileged Access Never)");
                details.push("ARM64 PAN: Available (hardware memory protection)".to_string());
            } else {
                // ARM64 still has basic XN (Execute Never) even without PAN
                protections.push("ARM64 XN (Execute Never)");
                details.push("ARM64 XN: Available (basic execute protection)".to_string());
            }
        } else {
            // x86/x64 NX bit check
            let nx_check = target
                .execute_command("grep -i nx /proc/cpuinfo | head -1")
                .await?;
            if !nx_check.stdout.is_empty() {
                protections.push("NX/DEP");
                details.push("NX support: Available".to_string());
            } else {
                details.push("NX support: Not detected".to_string());
            }
        }

        // Check kernel pointer restriction
        let kptr = target
            .execute_command("cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo '0'")
            .await?;
        if kptr.stdout.trim() == "2" {
            protections.push("KPTR_RESTRICT (strict)");
        } else if kptr.stdout.trim() == "1" {
            protections.push("KPTR_RESTRICT (basic)");
        } else {
            recommendations
                .push("Enable kernel pointer restriction: echo 1 > /proc/sys/kernel/kptr_restrict");
        }
        details.push(format!("KPTR_RESTRICT: {}", kptr.stdout.trim()));

        // Check dmesg restriction
        let dmesg_restrict = target
            .execute_command("cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo '0'")
            .await?;
        if dmesg_restrict.stdout.trim() == "1" {
            protections.push("DMESG_RESTRICT");
        } else {
            recommendations
                .push("Enable dmesg restriction: echo 1 > /proc/sys/kernel/dmesg_restrict");
        }
        details.push(format!("DMESG_RESTRICT: {}", dmesg_restrict.stdout.trim()));

        // Check SMEP/SMAP for x86 or equivalent ARM64 features
        if arch.stdout.trim() == "aarch64" {
            // Check for ARM64 Pointer Authentication
            let pauth_check = target
                .execute_command("grep -i 'paca\\|pacg' /proc/cpuinfo || echo 'not_found'")
                .await?;
            if pauth_check.stdout.contains("pac") {
                protections.push("ARM64 Pointer Authentication");
                details.push("ARM64 Pointer Authentication: Available".to_string());
            } else {
                details.push("ARM64 Pointer Authentication: Not available".to_string());
            }
        } else {
            let smep_smap = target
                .execute_command("grep -i 'smep\\|smap' /proc/cpuinfo || echo 'not_found'")
                .await?;
            if smep_smap.stdout.contains("smep") || smep_smap.stdout.contains("smap") {
                protections.push("SMEP/SMAP");
                details.push("SMEP/SMAP: Available".to_string());
            } else {
                details.push("SMEP/SMAP: Not available".to_string());
            }
        }

        // Add recommendations to details
        if !recommendations.is_empty() {
            details.push("".to_string());
            details.push("Recommendations to improve security:".to_string());
            for rec in &recommendations {
                details.push(format!("  • {}", rec));
            }
            details.push("".to_string());
            details.push("To make changes persistent, add to /etc/sysctl.conf:".to_string());
            if recommendations.iter().any(|r| r.contains("kptr_restrict")) {
                details.push("  kernel.kptr_restrict = 1".to_string());
            }
            if recommendations.iter().any(|r| r.contains("dmesg_restrict")) {
                details.push("  kernel.dmesg_restrict = 1".to_string());
            }
            if recommendations
                .iter()
                .any(|r| r.contains("randomize_va_space"))
            {
                details.push("  kernel.randomize_va_space = 2".to_string());
            }
        }

        let protection_count = protections.len();
        let details_str = details.join("\n");

        if protection_count >= 3 {
            Ok((
                TestStatus::Passed,
                format!("Kernel protections active: {:?}", protections),
                Some(details_str),
            ))
        } else if protection_count >= 2 {
            Ok((
                TestStatus::Warning,
                format!("Some kernel protections active: {:?}", protections),
                Some(details_str),
            ))
        } else {
            Ok((
                TestStatus::Failed,
                "Insufficient kernel protections detected".to_string(),
                Some(details_str),
            ))
        }
    }

    async fn test_readonly_filesystem(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        let mut details = Vec::new();
        let mut readonly_mounts = Vec::new();
        let mut writable_areas = Vec::new();
        let mut issues = Vec::new();

        // Check for Foundries.io LMP early so we can use it in logic
        let lmp_check = target
            .execute_command("cat /etc/os-release | grep -i 'linux.*micro.*platform\\|foundries'")
            .await?;
        let is_lmp = !lmp_check.stdout.is_empty();

        // Check mount points and their read-only status
        let mounts = target
            .execute_command("mount | grep -E '^/dev|^overlay|^tmpfs'")
            .await?;
        details.push(format!("Mount points:\n{}", mounts.stdout));

        // Check critical system directories that should be read-only
        let critical_dirs = ["/", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot"];

        for dir in &critical_dirs {
            let mount_check = target
                .execute_command(&format!(
                    "findmnt -n -o OPTIONS {} 2>/dev/null | grep -o 'ro\\|rw' | head -1",
                    dir
                ))
                .await?;
            let mount_status = mount_check.stdout.trim();

            if mount_status == "ro" {
                readonly_mounts.push(*dir);
            } else if mount_status == "rw" {
                // Check if this is expected for LMP/OSTree systems
                if *dir == "/" && is_lmp {
                    // Root might be rw but with OSTree - this is expected for LMP
                    let ostree_check = target
                        .execute_command("ostree --version 2>/dev/null")
                        .await?;
                    if !ostree_check.stdout.is_empty() {
                        readonly_mounts.push("/ (OSTree managed - RW overlay over RO base)");
                        details.push("Root filesystem is OSTree managed (read-only base with writable overlay)".to_string());
                    } else {
                        // Check for overlay
                        let overlay_check = target
                            .execute_command("mount | grep 'overlay on /'")
                            .await?;
                        if !overlay_check.stdout.is_empty() {
                            readonly_mounts.push("/ (overlay)");
                            details.push("Root filesystem uses overlay (read-only base with writable overlay)".to_string());
                        } else {
                            issues.push(format!(
                                "{} is mounted read-write (should be read-only)",
                                dir
                            ));
                        }
                    }
                } else if *dir == "/boot" && is_lmp {
                    // Boot partition might need to be RW for OTA updates in LMP
                    details.push(
                        "Boot partition is read-write (may be needed for OTA updates)".to_string(),
                    );
                    readonly_mounts.push("/boot (RW for OTA updates)");
                } else {
                    issues.push(format!(
                        "{} is mounted read-write (should be read-only)",
                        dir
                    ));
                }
            } else {
                details.push(format!("Could not determine mount status for {}", dir));
            }
        }

        // Check expected writable areas
        let writable_dirs = ["/var", "/tmp", "/home", "/opt", "/etc"];

        for dir in &writable_dirs {
            let mount_check = target
                .execute_command(&format!(
                    "findmnt -n -o OPTIONS {} 2>/dev/null | grep -o 'ro\\|rw' | head -1",
                    dir
                ))
                .await?;
            let mount_status = mount_check.stdout.trim();

            if mount_status == "rw" {
                writable_areas.push(*dir);
            } else if mount_status == "ro" {
                issues.push(format!(
                    "{} is read-only (should be writable for proper operation)",
                    dir
                ));
            }
        }

        // Check for Foundries.io LMP specific configurations (already checked above)
        if is_lmp {
            details.push("Detected Foundries.io Linux Micro Platform".to_string());

            // Check for OSTree (used by LMP for read-only root)
            let ostree_check = target
                .execute_command("ostree --version 2>/dev/null || echo 'not_found'")
                .await?;
            if !ostree_check.stdout.contains("not_found") {
                readonly_mounts.push("OSTree managed filesystem");
                details.push(format!("OSTree version: {}", ostree_check.stdout.trim()));
            }

            // Check for persistent data areas
            let persistent_check = target
                .execute_command("ls -la /var/sota /var/lib 2>/dev/null | head -5")
                .await?;
            if !persistent_check.stdout.is_empty() {
                details.push("Persistent data areas found in /var".to_string());
            }
        }

        // Test write protection by attempting to create a file in read-only areas
        let write_test = target
            .execute_command("touch /usr/test_readonly_check 2>&1 || echo 'write_blocked'")
            .await?;
        if write_test.stdout.contains("write_blocked") || write_test.stdout.contains("Read-only") {
            readonly_mounts.push("/usr (write-protected)");
            details.push("Write protection verified on /usr".to_string());
        } else {
            issues.push("WARNING: /usr allows write operations (security risk)".to_string());
            // Clean up test file if it was created
            let _ = target
                .execute_command("rm -f /usr/test_readonly_check")
                .await;
        }

        details.push(format!("Read-only mounts: {:?}", readonly_mounts));
        details.push(format!("Writable areas: {:?}", writable_areas));
        if !issues.is_empty() {
            details.push(format!("Issues found: {:?}", issues));
        }

        let details_str = Some(details.join("\n"));

        // Determine test result based on findings
        let readonly_count = readonly_mounts.len();
        let issue_count = issues.len();

        if readonly_count >= 3 && issue_count == 0 {
            Ok((
                TestStatus::Passed,
                format!(
                    "Read-only filesystem properly configured ({} protected areas)",
                    readonly_count
                ),
                details_str,
            ))
        } else if readonly_count >= 2 && issue_count <= 1 {
            Ok((
                TestStatus::Warning,
                format!(
                    "Mostly read-only filesystem ({} protected, {} issues)",
                    readonly_count, issue_count
                ),
                details_str,
            ))
        } else {
            Ok((
                TestStatus::Warning,
                format!(
                    "Insufficient read-only protection ({} protected, {} issues)",
                    readonly_count, issue_count
                ),
                details_str,
            ))
        }
    }

    async fn test_foundries_lmp_security(
        &self,
        target: &mut Target,
    ) -> Result<(TestStatus, String, Option<String>)> {
        let mut details = Vec::new();
        let mut lmp_features = Vec::new();
        let mut security_issues = Vec::new();

        // Check if this is a Foundries.io LMP system
        let lmp_check = target
            .execute_command("cat /etc/os-release | grep -i 'linux.*micro.*platform\\|foundries'")
            .await?;

        if lmp_check.stdout.is_empty() {
            return Ok((
                TestStatus::Skipped,
                "Not a Foundries.io LMP system".to_string(),
                None,
            ));
        }

        lmp_features.push("Foundries.io LMP detected");
        details.push(format!("LMP OS Release: {}", lmp_check.stdout.trim()));

        // Check OSTree status (immutable filesystem)
        let ostree_status = target
            .execute_command("ostree admin status 2>/dev/null || echo 'ostree_not_available'")
            .await?;

        if !ostree_status.stdout.contains("ostree_not_available") {
            lmp_features.push("OSTree immutable filesystem");
            details.push(format!(
                "OSTree status: {}",
                ostree_status
                    .stdout
                    .lines()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        } else {
            security_issues.push("OSTree not detected (LMP should use immutable filesystem)");
        }

        // Check aktualizr-lite OTA service
        let ota_service = target
            .execute_command("systemctl is-active aktualizr-lite 2>/dev/null || echo 'not_active'")
            .await?;

        if ota_service.stdout.trim() == "active" {
            lmp_features.push("OTA updates service active");
            details.push("aktualizr-lite: active".to_string());
        } else {
            security_issues.push("OTA update service not active");
        }

        // Check Docker/container security configuration
        let docker_info = target
            .execute_command("docker info 2>/dev/null | grep -E 'Security Options|User Namespaces' || echo 'docker_not_available'")
            .await?;

        if !docker_info.stdout.contains("docker_not_available") {
            if docker_info.stdout.contains("seccomp") {
                lmp_features.push("Docker seccomp security");
            }
            details.push(format!("Docker security: {}", docker_info.stdout.trim()));
        }

        // Check for LMP-specific hardening
        let lmp_hardening = target
            .execute_command(
                "systemctl list-units --type=service | grep -E 'fioconfig|lmp-' | wc -l",
            )
            .await?;

        let lmp_services: usize = lmp_hardening.stdout.trim().parse().unwrap_or(0);
        if lmp_services > 0 {
            lmp_features.push("LMP-specific services");
            details.push(format!("LMP services: {}", lmp_services));
        }

        // Check kernel security features for LMP
        let kernel_security = target
            .execute_command("cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
            .await?;

        if kernel_security.stdout.trim() == "2" {
            lmp_features.push("ASLR enabled");
        }

        // Check for secure boot indicators
        let secure_boot = target
            .execute_command("dmesg | grep -i 'secure.*boot\\|ahab\\|hab' | wc -l")
            .await?;

        let secure_boot_msgs: usize = secure_boot.stdout.trim().parse().unwrap_or(0);
        if secure_boot_msgs > 0 {
            lmp_features.push("Secure boot indicators");
            details.push(format!("Secure boot messages: {}", secure_boot_msgs));
        }

        // Check factory configuration
        let factory_config = target
            .execute_command("ls -la /var/sota/sql.db /var/lib/aktualizr-lite/ 2>/dev/null | wc -l")
            .await?;

        let config_files: usize = factory_config.stdout.trim().parse().unwrap_or(0);
        if config_files > 0 {
            lmp_features.push("Factory configuration present");
            details.push("Factory config: configured".to_string());
        }

        // Check for proper user configuration (fio user management)
        let user_config = target
            .execute_command("id fio 2>/dev/null && echo 'fio_user_exists' || echo 'no_fio_user'")
            .await?;

        if user_config.stdout.contains("fio_user_exists") {
            lmp_features.push("LMP user configuration");
        }

        // Check filesystem mount security
        let mount_security = target
            .execute_command("mount | grep -E 'ro,|nodev,|nosuid,' | wc -l")
            .await?;

        let secure_mounts: usize = mount_security.stdout.trim().parse().unwrap_or(0);
        if secure_mounts >= 3 {
            lmp_features.push("Secure filesystem mounts");
            details.push(format!("Secure mounts: {}", secure_mounts));
        }

        let details_str = if details.is_empty() {
            None
        } else {
            Some(details.join("\n"))
        };

        // Determine overall LMP security status
        let feature_count = lmp_features.len();
        let issue_count = security_issues.len();

        if feature_count >= 6 && issue_count == 0 {
            Ok((
                TestStatus::Passed,
                format!(
                    "Foundries.io LMP security excellent: {}",
                    lmp_features.join(", ")
                ),
                details_str,
            ))
        } else if feature_count >= 4 && issue_count <= 1 {
            Ok((
                TestStatus::Passed,
                format!(
                    "Foundries.io LMP security good: {} features, {} issues",
                    feature_count, issue_count
                ),
                details_str,
            ))
        } else if feature_count >= 3 {
            Ok((
                TestStatus::Warning,
                format!(
                    "Foundries.io LMP security needs attention: {} features, {} issues",
                    feature_count, issue_count
                ),
                details_str,
            ))
        } else {
            Ok((
                TestStatus::Failed,
                format!(
                    "Foundries.io LMP security insufficient: {} features, {} issues",
                    feature_count, issue_count
                ),
                details_str,
            ))
        }
    }
}
