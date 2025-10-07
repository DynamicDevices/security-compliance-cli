use crate::{
    error::Result,
    target::Target,
    tests::{create_test_result, SecurityTest, TestResult, TestStatus},
};
use async_trait::async_trait;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum ProductionTests {
    DebugInterfacesDisabled,
    DevelopmentToolsRemoved,
    DefaultCredentialsChanged,
    UnnecessaryServicesDisabled,
    LoggingConfigured,
    MonitoringEnabled,
    BackupSystemsActive,
    SecurityUpdatesEnabled,
    NetworkHardening,
    FileSystemHardening,
}

#[async_trait]
impl SecurityTest for ProductionTests {
    async fn run(&self, target: &mut Target) -> Result<TestResult> {
        let start_time = Instant::now();
        
        let result = match self {
            Self::DebugInterfacesDisabled => self.test_debug_interfaces_disabled(target).await,
            Self::DevelopmentToolsRemoved => self.test_development_tools_removed(target).await,
            Self::DefaultCredentialsChanged => self.test_default_credentials_changed(target).await,
            Self::UnnecessaryServicesDisabled => self.test_unnecessary_services_disabled(target).await,
            Self::LoggingConfigured => self.test_logging_configured(target).await,
            Self::MonitoringEnabled => self.test_monitoring_enabled(target).await,
            Self::BackupSystemsActive => self.test_backup_systems_active(target).await,
            Self::SecurityUpdatesEnabled => self.test_security_updates_enabled(target).await,
            Self::NetworkHardening => self.test_network_hardening(target).await,
            Self::FileSystemHardening => self.test_filesystem_hardening(target).await,
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
            Self::DebugInterfacesDisabled => "production_001",
            Self::DevelopmentToolsRemoved => "production_002",
            Self::DefaultCredentialsChanged => "production_003",
            Self::UnnecessaryServicesDisabled => "production_004",
            Self::LoggingConfigured => "production_005",
            Self::MonitoringEnabled => "production_006",
            Self::BackupSystemsActive => "production_007",
            Self::SecurityUpdatesEnabled => "production_008",
            Self::NetworkHardening => "production_009",
            Self::FileSystemHardening => "production_010",
        }
    }

    fn test_name(&self) -> &str {
        match self {
            Self::DebugInterfacesDisabled => "Debug Interfaces Disabled",
            Self::DevelopmentToolsRemoved => "Development Tools Removed",
            Self::DefaultCredentialsChanged => "Default Credentials Changed",
            Self::UnnecessaryServicesDisabled => "Unnecessary Services Disabled",
            Self::LoggingConfigured => "Production Logging Configured",
            Self::MonitoringEnabled => "System Monitoring Enabled",
            Self::BackupSystemsActive => "Backup Systems Active",
            Self::SecurityUpdatesEnabled => "Security Updates Enabled",
            Self::NetworkHardening => "Network Hardening Applied",
            Self::FileSystemHardening => "Filesystem Hardening Applied",
        }
    }

    fn category(&self) -> &str {
        "production"
    }

    fn description(&self) -> &str {
        match self {
            Self::DebugInterfacesDisabled => "Verify debug interfaces are disabled in production",
            Self::DevelopmentToolsRemoved => "Check that development tools are removed",
            Self::DefaultCredentialsChanged => "Verify default passwords and keys are changed",
            Self::UnnecessaryServicesDisabled => "Check that unnecessary services are disabled",
            Self::LoggingConfigured => "Verify production logging is properly configured",
            Self::MonitoringEnabled => "Check that system monitoring is enabled",
            Self::BackupSystemsActive => "Verify backup and recovery systems are active",
            Self::SecurityUpdatesEnabled => "Check that security updates are enabled",
            Self::NetworkHardening => "Verify network hardening measures are applied",
            Self::FileSystemHardening => "Check filesystem hardening configurations",
        }
    }
}

impl ProductionTests {
    async fn test_debug_interfaces_disabled(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for debug services
        let debug_services = target.execute_command("systemctl list-units --type=service | grep -E 'debug|gdb|strace|valgrind' || echo 'no_debug_services'").await?;
        
        // Check for debug ports
        let debug_ports = target.execute_command("netstat -tuln | grep -E ':1234|:4444|:8080|:9999' || echo 'no_debug_ports'").await?;
        
        // Check kernel debug options
        let kernel_debug = target.execute_command("cat /proc/cmdline | grep -E 'debug|verbose|loglevel=8' || echo 'no_kernel_debug'").await?;
        
        // Check for development filesystems
        let dev_filesystems = target.execute_command("mount | grep -E 'debugfs|tracefs' || echo 'no_dev_fs'").await?;
        
        let mut debug_issues = Vec::new();
        
        if !debug_services.stdout.contains("no_debug_services") {
            debug_issues.push("Debug services running");
        }
        if !debug_ports.stdout.contains("no_debug_ports") {
            debug_issues.push("Debug ports open");
        }
        if !kernel_debug.stdout.contains("no_kernel_debug") {
            debug_issues.push("Kernel debug enabled");
        }
        if !dev_filesystems.stdout.contains("no_dev_fs") {
            debug_issues.push("Debug filesystems mounted");
        }
        
        let details = format!("Debug services: {}\nDebug ports: {}\nKernel debug: {}\nDebug filesystems: {}", 
                             if debug_services.stdout.contains("no_debug_services") { "None" } else { "Present" },
                             if debug_ports.stdout.contains("no_debug_ports") { "None" } else { "Present" },
                             if kernel_debug.stdout.contains("no_kernel_debug") { "Disabled" } else { "Enabled" },
                             if dev_filesystems.stdout.contains("no_dev_fs") { "None" } else { "Present" });
        
        if debug_issues.is_empty() {
            Ok((TestStatus::Passed, "Debug interfaces properly disabled".to_string(), Some(details)))
        } else if debug_issues.len() <= 1 {
            Ok((TestStatus::Warning, format!("Some debug interfaces present: {:?}", debug_issues), Some(details)))
        } else {
            Ok((TestStatus::Failed, format!("Multiple debug interfaces active: {:?}", debug_issues), Some(details)))
        }
    }

    async fn test_development_tools_removed(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for common development tools
        let dev_tools = ["gcc", "g++", "make", "cmake", "git", "vim", "emacs", "nano", "gdb", "strace", "valgrind"];
        let mut found_tools = Vec::new();
        
        for tool in &dev_tools {
            let tool_check = target.execute_command(&format!("which {} 2>/dev/null || echo 'not_found'", tool)).await?;
            if !tool_check.stdout.contains("not_found") {
                found_tools.push(*tool);
            }
        }
        
        // Check for development packages
        let dev_packages = target.execute_command("dpkg -l 2>/dev/null | grep -E 'build-essential|development|dev-' | wc -l || rpm -qa 2>/dev/null | grep -E 'devel|build' | wc -l || echo '0'").await?;
        
        // Check for source code directories
        let source_dirs = target.execute_command("find /usr/src /opt -maxdepth 2 -type d -name '*src*' -o -name '*source*' 2>/dev/null | wc -l").await?;
        
        let dev_pkg_count: usize = dev_packages.stdout.trim().parse().unwrap_or(0);
        let src_dir_count: usize = source_dirs.stdout.trim().parse().unwrap_or(0);
        
        let details = format!("Development tools found: {:?}\nDev packages: {}\nSource directories: {}", 
                             found_tools, dev_pkg_count, src_dir_count);
        
        if found_tools.is_empty() && dev_pkg_count == 0 && src_dir_count == 0 {
            Ok((TestStatus::Passed, "Development tools properly removed".to_string(), Some(details)))
        } else if found_tools.len() <= 2 && dev_pkg_count <= 2 {
            Ok((TestStatus::Warning, "Some development tools remain".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Many development tools still present".to_string(), Some(details)))
        }
    }

    async fn test_default_credentials_changed(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for default users with default passwords
        let _default_users = ["admin", "root", "user", "test", "demo", "guest"];
        let mut credential_issues = Vec::new();
        
        // Check for users with UID 0 (should only be root)
        let root_users = target.execute_command("awk -F: '$3 == 0 { print $1 }' /etc/passwd").await?;
        let root_count = root_users.stdout.lines().filter(|line| !line.trim().is_empty()).count();
        
        // Check for users with no password
        let no_password = target.execute_command("awk -F: '$2 == \"\" { print $1 }' /etc/shadow 2>/dev/null | wc -l || echo '0'").await?;
        
        // Check SSH key authentication
        let ssh_keys = target.execute_command("find /home -name '.ssh' -type d -exec find {} -name 'authorized_keys' \\; 2>/dev/null | wc -l").await?;
        
        // Check for default SSH host keys
        let ssh_host_keys = target.execute_command("ls -la /etc/ssh/ssh_host_*key* 2>/dev/null | wc -l").await?;
        
        if root_count > 1 {
            credential_issues.push("Multiple root users");
        }
        
        let no_pwd_count: usize = no_password.stdout.trim().parse().unwrap_or(0);
        if no_pwd_count > 0 {
            credential_issues.push("Users without passwords");
        }
        
        let ssh_key_count: usize = ssh_keys.stdout.trim().parse().unwrap_or(0);
        let host_key_count: usize = ssh_host_keys.stdout.trim().parse().unwrap_or(0);
        
        let details = format!("Root users: {}\nUsers without passwords: {}\nSSH keys: {}\nHost keys: {}", 
                             root_count, no_pwd_count, ssh_key_count, host_key_count);
        
        if credential_issues.is_empty() && ssh_key_count > 0 && host_key_count > 0 {
            Ok((TestStatus::Passed, "Default credentials properly changed".to_string(), Some(details)))
        } else if credential_issues.len() <= 1 {
            Ok((TestStatus::Warning, "Some credential issues detected".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, format!("Multiple credential issues: {:?}", credential_issues), Some(details)))
        }
    }

    async fn test_unnecessary_services_disabled(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for unnecessary services
        let unnecessary_services = ["telnet", "ftp", "rsh", "rlogin", "tftp", "finger", "chargen", "daytime", "echo", "discard"];
        let mut running_unnecessary = Vec::new();
        
        let all_services = target.execute_command("systemctl list-units --type=service --state=running --no-pager").await?;
        
        for service in &unnecessary_services {
            if all_services.stdout.contains(service) {
                running_unnecessary.push(*service);
            }
        }
        
        // Check total number of running services
        let service_count = target.execute_command("systemctl list-units --type=service --state=running --no-pager | grep -c '.service' || echo '0'").await?;
        
        // Check for X11/GUI services
        let gui_services = target.execute_command("systemctl list-units --type=service --state=running | grep -E 'gdm|lightdm|sddm|xdm|x11' || echo 'no_gui'").await?;
        
        let total_services: usize = service_count.stdout.trim().parse().unwrap_or(0);
        
        let details = format!("Unnecessary services running: {:?}\nTotal services: {}\nGUI services: {}", 
                             running_unnecessary, total_services, 
                             if gui_services.stdout.contains("no_gui") { "None" } else { "Present" });
        
        if running_unnecessary.is_empty() && total_services <= 25 {
            Ok((TestStatus::Passed, "Unnecessary services properly disabled".to_string(), Some(details)))
        } else if running_unnecessary.len() <= 1 && total_services <= 35 {
            Ok((TestStatus::Warning, "Some unnecessary services may be running".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Many unnecessary services running".to_string(), Some(details)))
        }
    }

    async fn test_logging_configured(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check syslog configuration
        let syslog_status = target.execute_command("systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog-ng 2>/dev/null || echo 'no_syslog'").await?;
        
        // Check log rotation
        let logrotate_config = target.execute_command("ls -la /etc/logrotate.d/ | wc -l").await?;
        
        // Check log files
        let log_files = target.execute_command("find /var/log -name '*.log' -type f | wc -l").await?;
        
        // Check remote logging
        let remote_logging = target.execute_command("grep -E 'remote|@' /etc/rsyslog.conf /etc/syslog-ng/syslog-ng.conf 2>/dev/null | wc -l").await?;
        
        // Check audit logging
        let audit_status = target.execute_command("systemctl is-active auditd 2>/dev/null || echo 'no_audit'").await?;
        
        let logrotate_count: usize = logrotate_config.stdout.trim().parse().unwrap_or(0);
        let log_file_count: usize = log_files.stdout.trim().parse().unwrap_or(0);
        let remote_log_count: usize = remote_logging.stdout.trim().parse().unwrap_or(0);
        
        let mut logging_features = Vec::new();
        
        if syslog_status.stdout.trim() == "active" {
            logging_features.push("System logging active");
        }
        if logrotate_count > 5 {
            logging_features.push("Log rotation configured");
        }
        if log_file_count > 10 {
            logging_features.push("Log files present");
        }
        if remote_log_count > 0 {
            logging_features.push("Remote logging configured");
        }
        if audit_status.stdout.trim() == "active" {
            logging_features.push("Audit logging active");
        }
        
        let details = format!("Syslog: {}\nLogrotate configs: {}\nLog files: {}\nRemote logging: {}\nAudit: {}", 
                             syslog_status.stdout.trim(), logrotate_count, log_file_count, 
                             remote_log_count, audit_status.stdout.trim());
        
        if logging_features.len() >= 4 {
            Ok((TestStatus::Passed, "Production logging properly configured".to_string(), Some(details)))
        } else if logging_features.len() >= 3 {
            Ok((TestStatus::Warning, "Basic logging configured".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Insufficient logging configuration".to_string(), Some(details)))
        }
    }

    async fn test_monitoring_enabled(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for monitoring agents
        let monitoring_tools = ["prometheus", "node_exporter", "collectd", "telegraf", "zabbix", "nagios"];
        let mut active_monitoring = Vec::new();
        
        for tool in &monitoring_tools {
            let tool_check = target.execute_command(&format!("systemctl is-active {} 2>/dev/null", tool)).await?;
            if tool_check.stdout.trim() == "active" {
                active_monitoring.push(*tool);
            }
        }
        
        // Check system monitoring
        let system_stats = target.execute_command("which top 2>/dev/null && which ps 2>/dev/null && which iostat 2>/dev/null || echo 'basic_tools_missing'").await?;
        
        // Check log monitoring
        let log_monitoring = target.execute_command("ps aux | grep -E 'logwatch|fail2ban|swatch' | grep -v grep || echo 'no_log_monitoring'").await?;
        
        // Check network monitoring
        let network_monitoring = target.execute_command("which netstat 2>/dev/null && which ss 2>/dev/null || echo 'network_tools_missing'").await?;
        
        let details = format!("Active monitoring: {:?}\nSystem tools: {}\nLog monitoring: {}\nNetwork tools: {}", 
                             active_monitoring, 
                             if system_stats.stdout.contains("basic_tools_missing") { "Missing" } else { "Available" },
                             if log_monitoring.stdout.contains("no_log_monitoring") { "None" } else { "Active" },
                             if network_monitoring.stdout.contains("network_tools_missing") { "Missing" } else { "Available" });
        
        if active_monitoring.len() >= 2 {
            Ok((TestStatus::Passed, "Comprehensive monitoring enabled".to_string(), Some(details)))
        } else if active_monitoring.len() >= 1 || !system_stats.stdout.contains("basic_tools_missing") {
            Ok((TestStatus::Warning, "Basic monitoring available".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Insufficient monitoring configuration".to_string(), Some(details)))
        }
    }

    async fn test_backup_systems_active(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for backup tools
        let backup_tools = ["rsync", "tar", "borgbackup", "restic", "duplicity"];
        let mut available_tools = Vec::new();
        
        for tool in &backup_tools {
            let tool_check = target.execute_command(&format!("which {} 2>/dev/null", tool)).await?;
            if !tool_check.stdout.trim().is_empty() {
                available_tools.push(*tool);
            }
        }
        
        // Check for backup cron jobs
        let backup_crons = target.execute_command("crontab -l 2>/dev/null | grep -E 'backup|rsync|tar' | wc -l").await?;
        
        // Check for backup directories
        let backup_dirs = target.execute_command("find /backup /var/backup /home/backup -type d 2>/dev/null | wc -l").await?;
        
        // Check backup services
        let backup_services = target.execute_command("systemctl list-units --type=service | grep -E 'backup|sync' || echo 'no_backup_services'").await?;
        
        let cron_count: usize = backup_crons.stdout.trim().parse().unwrap_or(0);
        let backup_dir_count: usize = backup_dirs.stdout.trim().parse().unwrap_or(0);
        
        let mut backup_features = Vec::new();
        
        if !available_tools.is_empty() {
            backup_features.push("Backup tools available");
        }
        if cron_count > 0 {
            backup_features.push("Scheduled backups");
        }
        if backup_dir_count > 0 {
            backup_features.push("Backup directories");
        }
        if !backup_services.stdout.contains("no_backup_services") {
            backup_features.push("Backup services");
        }
        
        let details = format!("Available tools: {:?}\nScheduled backups: {}\nBackup directories: {}\nBackup services: {}", 
                             available_tools, cron_count, backup_dir_count,
                             if backup_services.stdout.contains("no_backup_services") { "None" } else { "Active" });
        
        if backup_features.len() >= 3 {
            Ok((TestStatus::Passed, "Backup systems properly configured".to_string(), Some(details)))
        } else if backup_features.len() >= 2 {
            Ok((TestStatus::Warning, "Basic backup systems available".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Insufficient backup systems".to_string(), Some(details)))
        }
    }

    async fn test_security_updates_enabled(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check automatic updates
        let auto_updates = target.execute_command("systemctl is-active unattended-upgrades 2>/dev/null || systemctl is-active dnf-automatic 2>/dev/null || echo 'no_auto_updates'").await?;
        
        // Check update configuration
        let update_config = target.execute_command("ls -la /etc/apt/apt.conf.d/*unattended* /etc/dnf/automatic.conf 2>/dev/null | wc -l").await?;
        
        // Check last update time
        let last_update = target.execute_command("stat -c %Y /var/lib/apt/lists/* 2>/dev/null | sort -n | tail -1 | xargs -I {} date -d @{} 2>/dev/null || stat -c %Y /var/cache/dnf/* 2>/dev/null | sort -n | tail -1 | xargs -I {} date -d @{} 2>/dev/null || echo 'no_update_info'").await?;
        
        // Check security repositories
        let security_repos = target.execute_command("grep -r security /etc/apt/sources.list* 2>/dev/null | wc -l || grep -r security /etc/yum.repos.d/ 2>/dev/null | wc -l || echo '0'").await?;
        
        let config_count: usize = update_config.stdout.trim().parse().unwrap_or(0);
        let security_repo_count: usize = security_repos.stdout.trim().parse().unwrap_or(0);
        
        let mut update_features = Vec::new();
        
        if auto_updates.stdout.trim() == "active" {
            update_features.push("Automatic updates enabled");
        }
        if config_count > 0 {
            update_features.push("Update configuration present");
        }
        if !last_update.stdout.contains("no_update_info") {
            update_features.push("Recent update activity");
        }
        if security_repo_count > 0 {
            update_features.push("Security repositories configured");
        }
        
        let details = format!("Auto updates: {}\nConfigurations: {}\nLast update: {}\nSecurity repos: {}", 
                             auto_updates.stdout.trim(), config_count, 
                             if last_update.stdout.contains("no_update_info") { "Unknown" } else { "Available" },
                             security_repo_count);
        
        if update_features.len() >= 3 {
            Ok((TestStatus::Passed, "Security updates properly enabled".to_string(), Some(details)))
        } else if update_features.len() >= 2 {
            Ok((TestStatus::Warning, "Basic update mechanisms available".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Security updates not properly configured".to_string(), Some(details)))
        }
    }

    async fn test_network_hardening(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check firewall status
        let firewall_status = target.execute_command("systemctl is-active iptables 2>/dev/null || systemctl is-active ufw 2>/dev/null || systemctl is-active firewalld 2>/dev/null || echo 'no_firewall'").await?;
        
        // Check network parameters
        let net_params = target.execute_command("sysctl net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.all.accept_redirects 2>/dev/null || echo 'no_sysctl'").await?;
        
        // Check for unnecessary network services
        let network_services = target.execute_command("netstat -tuln | grep -E ':21|:23|:25|:53|:69|:135|:139|:445' | wc -l").await?;
        
        // Check TCP wrappers
        let tcp_wrappers = target.execute_command("ls -la /etc/hosts.allow /etc/hosts.deny 2>/dev/null | wc -l").await?;
        
        let risky_services: usize = network_services.stdout.trim().parse().unwrap_or(0);
        let wrapper_files: usize = tcp_wrappers.stdout.trim().parse().unwrap_or(0);
        
        let mut hardening_features = Vec::new();
        
        if firewall_status.stdout.trim() == "active" {
            hardening_features.push("Firewall active");
        }
        if net_params.stdout.contains("ip_forward = 0") {
            hardening_features.push("IP forwarding disabled");
        }
        if risky_services == 0 {
            hardening_features.push("No risky network services");
        }
        if wrapper_files >= 2 {
            hardening_features.push("TCP wrappers configured");
        }
        
        let details = format!("Firewall: {}\nNetwork params: {}\nRisky services: {}\nTCP wrappers: {}", 
                             firewall_status.stdout.trim(), 
                             if net_params.stdout.contains("no_sysctl") { "Not available" } else { "Available" },
                             risky_services, wrapper_files);
        
        if hardening_features.len() >= 3 {
            Ok((TestStatus::Passed, "Network hardening properly applied".to_string(), Some(details)))
        } else if hardening_features.len() >= 2 {
            Ok((TestStatus::Warning, "Basic network hardening applied".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Insufficient network hardening".to_string(), Some(details)))
        }
    }

    async fn test_filesystem_hardening(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check mount options
        let secure_mounts = target.execute_command("mount | grep -E 'nodev|nosuid|noexec' | wc -l").await?;
        
        // Check file permissions on critical files
        let critical_perms = target.execute_command("ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null | grep -E '^-r--------' | wc -l").await?;
        
        // Check for world-writable files
        let world_writable = target.execute_command("find /etc /usr/bin /usr/sbin -type f -perm -002 2>/dev/null | wc -l").await?;
        
        // Check umask setting
        let umask_check = target.execute_command("grep -E '^umask' /etc/profile /etc/bash.bashrc /etc/login.defs 2>/dev/null | grep -E '022|027|077' | wc -l").await?;
        
        let secure_mount_count: usize = secure_mounts.stdout.trim().parse().unwrap_or(0);
        let secure_perm_count: usize = critical_perms.stdout.trim().parse().unwrap_or(0);
        let world_write_count: usize = world_writable.stdout.trim().parse().unwrap_or(0);
        let umask_count: usize = umask_check.stdout.trim().parse().unwrap_or(0);
        
        let mut hardening_features = Vec::new();
        
        if secure_mount_count > 5 {
            hardening_features.push("Secure mount options");
        }
        if secure_perm_count >= 2 {
            hardening_features.push("Critical file permissions secure");
        }
        if world_write_count == 0 {
            hardening_features.push("No world-writable files");
        }
        if umask_count > 0 {
            hardening_features.push("Secure umask configured");
        }
        
        let details = format!("Secure mounts: {}\nSecure permissions: {}\nWorld-writable files: {}\nUmask configs: {}", 
                             secure_mount_count, secure_perm_count, world_write_count, umask_count);
        
        if hardening_features.len() >= 3 {
            Ok((TestStatus::Passed, "Filesystem hardening properly applied".to_string(), Some(details)))
        } else if hardening_features.len() >= 2 {
            Ok((TestStatus::Warning, "Basic filesystem hardening applied".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Insufficient filesystem hardening".to_string(), Some(details)))
        }
    }
}
