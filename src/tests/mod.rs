use crate::{
    cli::{TestMode, TestSuite},
    error::Result,
    target::{Target, SystemInfo},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

pub mod boot;
pub mod hardware;
pub mod network;
pub mod runtime;
pub mod compliance;
pub mod container;
pub mod certificate;
pub mod production;

pub use boot::BootSecurityTests;
pub use hardware::HardwareSecurityTests;
pub use network::NetworkSecurityTests;
pub use runtime::RuntimeSecurityTests;
pub use compliance::ComplianceTests;
pub use container::ContainerSecurityTests;
pub use certificate::CertificateTests;
pub use production::ProductionTests;

#[async_trait]
pub trait SecurityTest {
    async fn run(&self, target: &mut Target) -> Result<TestResult>;
    fn test_id(&self) -> &str;
    fn test_name(&self) -> &str;
    fn category(&self) -> &str;
    fn description(&self) -> &str;
}

// Unified enum for all security tests
#[derive(Debug, Clone)]
pub enum SecurityTestEnum {
    Boot(BootSecurityTests),
    Hardware(HardwareSecurityTests),
    Network(NetworkSecurityTests),
    Runtime(RuntimeSecurityTests),
    Compliance(ComplianceTests),
    Container(ContainerSecurityTests),
    Certificate(CertificateTests),
    Production(ProductionTests),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub test_id: String,
    pub test_name: String,
    pub category: String,
    pub status: TestStatus,
    pub message: String,
    pub details: Option<String>,
    pub duration: Duration,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TestStatus {
    Passed,
    Failed,
    Warning,
    Skipped,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuiteResults {
    pub suite_name: String,
    pub total_tests: usize,
    pub passed: usize,
    pub failed: usize,
    pub warnings: usize,
    pub skipped: usize,
    pub errors: usize,
    pub duration: Duration,
    pub timestamp: DateTime<Utc>,
    pub system_info: SystemInfo,
    pub results: Vec<TestResult>,
}

impl TestSuiteResults {
    pub fn overall_passed(&self) -> bool {
        self.failed == 0 && self.errors == 0
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            return 100.0;
        }
        (self.passed as f64 / self.total_tests as f64) * 100.0
    }
}

#[async_trait]
impl SecurityTest for SecurityTestEnum {
    async fn run(&self, target: &mut Target) -> Result<TestResult> {
        match self {
            SecurityTestEnum::Boot(test) => test.run(target).await,
            SecurityTestEnum::Hardware(test) => test.run(target).await,
            SecurityTestEnum::Network(test) => test.run(target).await,
            SecurityTestEnum::Runtime(test) => test.run(target).await,
            SecurityTestEnum::Compliance(test) => test.run(target).await,
            SecurityTestEnum::Container(test) => test.run(target).await,
            SecurityTestEnum::Certificate(test) => test.run(target).await,
            SecurityTestEnum::Production(test) => test.run(target).await,
        }
    }

    fn test_id(&self) -> &str {
        match self {
            SecurityTestEnum::Boot(test) => test.test_id(),
            SecurityTestEnum::Hardware(test) => test.test_id(),
            SecurityTestEnum::Network(test) => test.test_id(),
            SecurityTestEnum::Runtime(test) => test.test_id(),
            SecurityTestEnum::Compliance(test) => test.test_id(),
            SecurityTestEnum::Container(test) => test.test_id(),
            SecurityTestEnum::Certificate(test) => test.test_id(),
            SecurityTestEnum::Production(test) => test.test_id(),
        }
    }

    fn test_name(&self) -> &str {
        match self {
            SecurityTestEnum::Boot(test) => test.test_name(),
            SecurityTestEnum::Hardware(test) => test.test_name(),
            SecurityTestEnum::Network(test) => test.test_name(),
            SecurityTestEnum::Runtime(test) => test.test_name(),
            SecurityTestEnum::Compliance(test) => test.test_name(),
            SecurityTestEnum::Container(test) => test.test_name(),
            SecurityTestEnum::Certificate(test) => test.test_name(),
            SecurityTestEnum::Production(test) => test.test_name(),
        }
    }

    fn category(&self) -> &str {
        match self {
            SecurityTestEnum::Boot(test) => test.category(),
            SecurityTestEnum::Hardware(test) => test.category(),
            SecurityTestEnum::Network(test) => test.category(),
            SecurityTestEnum::Runtime(test) => test.category(),
            SecurityTestEnum::Compliance(test) => test.category(),
            SecurityTestEnum::Container(test) => test.category(),
            SecurityTestEnum::Certificate(test) => test.category(),
            SecurityTestEnum::Production(test) => test.category(),
        }
    }

    fn description(&self) -> &str {
        match self {
            SecurityTestEnum::Boot(test) => test.description(),
            SecurityTestEnum::Hardware(test) => test.description(),
            SecurityTestEnum::Network(test) => test.description(),
            SecurityTestEnum::Runtime(test) => test.description(),
            SecurityTestEnum::Compliance(test) => test.description(),
            SecurityTestEnum::Container(test) => test.description(),
            SecurityTestEnum::Certificate(test) => test.description(),
            SecurityTestEnum::Production(test) => test.description(),
        }
    }
}

pub struct TestRegistry {
    tests: HashMap<String, SecurityTestEnum>,
}

impl TestRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            tests: HashMap::new(),
        };
        
        // Register all test categories
        registry.register_boot_tests();
        registry.register_hardware_tests();
        registry.register_runtime_tests();
        registry.register_network_tests();
        registry.register_compliance_tests();
        registry.register_container_tests();
        registry.register_certificate_tests();
        registry.register_production_tests();
        
        registry
    }

    fn register_boot_tests(&mut self) {
        // Boot security tests
        self.register(SecurityTestEnum::Boot(BootSecurityTests::SecureBootEnabled));
        self.register(SecurityTestEnum::Boot(BootSecurityTests::UBootSigned));
        self.register(SecurityTestEnum::Boot(BootSecurityTests::KernelSigned));
        self.register(SecurityTestEnum::Boot(BootSecurityTests::ModuleSigning));
        self.register(SecurityTestEnum::Boot(BootSecurityTests::OpteeSigned));
        self.register(SecurityTestEnum::Boot(BootSecurityTests::TfaSigned));
        self.register(SecurityTestEnum::Boot(BootSecurityTests::BootChainVerification));
    }

    fn register_hardware_tests(&mut self) {
        // Hardware security tests
        self.register(SecurityTestEnum::Hardware(HardwareSecurityTests::EdgeLockEnclave));
        self.register(SecurityTestEnum::Hardware(HardwareSecurityTests::SecureEnclaveStatus));
        self.register(SecurityTestEnum::Hardware(HardwareSecurityTests::HardwareRootOfTrust));
        self.register(SecurityTestEnum::Hardware(HardwareSecurityTests::CryptoAcceleration));
        self.register(SecurityTestEnum::Hardware(HardwareSecurityTests::RandomNumberGenerator));
    }

    fn register_runtime_tests(&mut self) {
        // Runtime security tests
        self.register(SecurityTestEnum::Runtime(RuntimeSecurityTests::FilesystemEncryption));
        self.register(SecurityTestEnum::Runtime(RuntimeSecurityTests::FirewallActive));
        self.register(SecurityTestEnum::Runtime(RuntimeSecurityTests::SelinuxStatus));
        self.register(SecurityTestEnum::Runtime(RuntimeSecurityTests::SshConfiguration));
        self.register(SecurityTestEnum::Runtime(RuntimeSecurityTests::UserPermissions));
        self.register(SecurityTestEnum::Runtime(RuntimeSecurityTests::ServiceHardening));
        self.register(SecurityTestEnum::Runtime(RuntimeSecurityTests::KernelProtections));
    }

    fn register_network_tests(&mut self) {
        // Network security tests
        self.register(SecurityTestEnum::Network(NetworkSecurityTests::OpenPorts));
        self.register(SecurityTestEnum::Network(NetworkSecurityTests::NetworkServices));
        self.register(SecurityTestEnum::Network(NetworkSecurityTests::WifiSecurity));
        self.register(SecurityTestEnum::Network(NetworkSecurityTests::BluetoothSecurity));
        self.register(SecurityTestEnum::Network(NetworkSecurityTests::NetworkEncryption));
    }

    fn register_compliance_tests(&mut self) {
        // Compliance-specific tests
        self.register(SecurityTestEnum::Compliance(ComplianceTests::CraDataProtection));
        self.register(SecurityTestEnum::Compliance(ComplianceTests::CraVulnerabilityManagement));
        self.register(SecurityTestEnum::Compliance(ComplianceTests::RedSecurityRequirements));
        self.register(SecurityTestEnum::Compliance(ComplianceTests::IncidentResponse));
        self.register(SecurityTestEnum::Compliance(ComplianceTests::AuditLogging));
    }

    fn register_container_tests(&mut self) {
        // Container security tests
        self.register(SecurityTestEnum::Container(ContainerSecurityTests::DockerSecurityConfig));
        self.register(SecurityTestEnum::Container(ContainerSecurityTests::ContainerImageSecurity));
        self.register(SecurityTestEnum::Container(ContainerSecurityTests::RuntimeSecurity));
        self.register(SecurityTestEnum::Container(ContainerSecurityTests::NetworkIsolation));
        self.register(SecurityTestEnum::Container(ContainerSecurityTests::UserNamespaces));
        self.register(SecurityTestEnum::Container(ContainerSecurityTests::SelinuxContexts));
        self.register(SecurityTestEnum::Container(ContainerSecurityTests::SeccompProfiles));
    }

    fn register_certificate_tests(&mut self) {
        // Certificate management tests
        self.register(SecurityTestEnum::Certificate(CertificateTests::X509Validation));
        self.register(SecurityTestEnum::Certificate(CertificateTests::PkiInfrastructure));
        self.register(SecurityTestEnum::Certificate(CertificateTests::CertificateExpiration));
        self.register(SecurityTestEnum::Certificate(CertificateTests::CertificateChain));
        self.register(SecurityTestEnum::Certificate(CertificateTests::CertificateRevocation));
        self.register(SecurityTestEnum::Certificate(CertificateTests::SecureCertStorage));
        self.register(SecurityTestEnum::Certificate(CertificateTests::CaCertManagement));
        self.register(SecurityTestEnum::Certificate(CertificateTests::TlsCertValidation));
        self.register(SecurityTestEnum::Certificate(CertificateTests::CertificateRotation));
        self.register(SecurityTestEnum::Certificate(CertificateTests::ComplianceStandards));
    }

    fn register_production_tests(&mut self) {
        // Production hardening tests
        self.register(SecurityTestEnum::Production(ProductionTests::DebugInterfacesDisabled));
        self.register(SecurityTestEnum::Production(ProductionTests::DevelopmentToolsRemoved));
        self.register(SecurityTestEnum::Production(ProductionTests::DefaultCredentialsChanged));
        self.register(SecurityTestEnum::Production(ProductionTests::UnnecessaryServicesDisabled));
        self.register(SecurityTestEnum::Production(ProductionTests::LoggingConfigured));
        self.register(SecurityTestEnum::Production(ProductionTests::MonitoringEnabled));
        self.register(SecurityTestEnum::Production(ProductionTests::BackupSystemsActive));
        self.register(SecurityTestEnum::Production(ProductionTests::SecurityUpdatesEnabled));
        self.register(SecurityTestEnum::Production(ProductionTests::NetworkHardening));
        self.register(SecurityTestEnum::Production(ProductionTests::FileSystemHardening));
    }

    fn register(&mut self, test: SecurityTestEnum) {
        self.tests.insert(test.test_id().to_string(), test);
    }

    pub fn get_tests_for_suite_and_mode(&self, suite: &TestSuite, mode: &TestMode) -> Vec<&str> {
        let mut test_ids = self.get_tests_for_suite(suite);
        
        // Filter tests based on mode
        match mode {
            TestMode::PreProduction => {
                // In pre-production mode, exclude production-specific tests
                test_ids.retain(|test_id| !test_id.starts_with("production_"));
            }
            TestMode::Production => {
                // In production mode, include all tests
                // Production tests are mandatory in production mode
            }
        }
        
        test_ids
    }

    pub fn get_tests_for_suite(&self, suite: &TestSuite) -> Vec<&str> {
        match suite {
            TestSuite::All => self.tests.keys().map(|k| k.as_str()).collect(),
            TestSuite::Boot => self.get_tests_by_category("boot"),
            TestSuite::Runtime => self.get_tests_by_category("runtime"),
            TestSuite::Hardware => self.get_tests_by_category("hardware"),
            TestSuite::Network => self.get_tests_by_category("network"),
            TestSuite::Compliance => self.get_tests_by_category("compliance"),
            TestSuite::Container => self.get_tests_by_category("container"),
            TestSuite::Certificate => self.get_tests_by_category("certificate"),
            TestSuite::Production => self.get_tests_by_category("production"),
            TestSuite::Custom => {
                // TODO: Load from config file
                vec![]
            }
        }
    }

    fn get_tests_by_category(&self, category: &str) -> Vec<&str> {
        self.tests
            .iter()
            .filter(|(_, test)| test.category() == category)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    pub fn get_test(&self, test_id: &str) -> Option<&SecurityTestEnum> {
        self.tests.get(test_id)
    }

    pub fn list_tests(&self) {
        println!("Available Security Compliance Tests:");
        println!("==================================");
        
        let mut categories: HashMap<String, Vec<&str>> = HashMap::new();
        
        for (test_id, test) in &self.tests {
            categories
                .entry(test.category().to_string())
                .or_insert_with(Vec::new)
                .push(test_id);
        }

        for (category, test_ids) in categories {
            println!("\n📁 {} Tests:", category.to_uppercase());
            for test_id in test_ids {
                if let Some(test) = self.get_test(test_id) {
                    println!("  🔍 {} - {}", test.test_id(), test.test_name());
                    println!("      {}", test.description());
                }
            }
        }
    }
}

pub fn list_available_tests() {
    let registry = TestRegistry::new();
    registry.list_tests();
}

// Helper functions for common test patterns
pub fn create_test_result(
    test_id: &str,
    test_name: &str,
    category: &str,
    status: TestStatus,
    message: &str,
    details: Option<String>,
    duration: Duration,
) -> TestResult {
    TestResult {
        test_id: test_id.to_string(),
        test_name: test_name.to_string(),
        category: category.to_string(),
        status,
        message: message.to_string(),
        details,
        duration,
        timestamp: Utc::now(),
        metadata: HashMap::new(),
    }
}

pub async fn check_command_success(
    target: &mut Target,
    command: &str,
    expected_pattern: Option<&str>,
) -> Result<bool> {
    let result = target.execute_command(command).await?;
    
    if result.exit_code != 0 {
        return Ok(false);
    }

    if let Some(pattern) = expected_pattern {
        let regex = regex::Regex::new(pattern)?;
        Ok(regex.is_match(&result.stdout))
    } else {
        Ok(true)
    }
}
