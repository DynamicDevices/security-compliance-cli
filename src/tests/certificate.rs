use crate::{
    error::Result,
    target::Target,
    tests::{create_test_result, SecurityTest, TestResult, TestStatus},
};
use async_trait::async_trait;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum CertificateTests {
    X509Validation,
    PkiInfrastructure,
    CertificateExpiration,
    CertificateChain,
    CertificateRevocation,
    SecureCertStorage,
    CaCertManagement,
    TlsCertValidation,
    CertificateRotation,
    ComplianceStandards,
}

#[async_trait]
impl SecurityTest for CertificateTests {
    async fn run(&self, target: &mut Target) -> Result<TestResult> {
        let start_time = Instant::now();
        
        let result = match self {
            Self::X509Validation => self.test_x509_validation(target).await,
            Self::PkiInfrastructure => self.test_pki_infrastructure(target).await,
            Self::CertificateExpiration => self.test_certificate_expiration(target).await,
            Self::CertificateChain => self.test_certificate_chain(target).await,
            Self::CertificateRevocation => self.test_certificate_revocation(target).await,
            Self::SecureCertStorage => self.test_secure_cert_storage(target).await,
            Self::CaCertManagement => self.test_ca_cert_management(target).await,
            Self::TlsCertValidation => self.test_tls_cert_validation(target).await,
            Self::CertificateRotation => self.test_certificate_rotation(target).await,
            Self::ComplianceStandards => self.test_compliance_standards(target).await,
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
            Self::X509Validation => "certificate_001",
            Self::PkiInfrastructure => "certificate_002",
            Self::CertificateExpiration => "certificate_003",
            Self::CertificateChain => "certificate_004",
            Self::CertificateRevocation => "certificate_005",
            Self::SecureCertStorage => "certificate_006",
            Self::CaCertManagement => "certificate_007",
            Self::TlsCertValidation => "certificate_008",
            Self::CertificateRotation => "certificate_009",
            Self::ComplianceStandards => "certificate_010",
        }
    }

    fn test_name(&self) -> &str {
        match self {
            Self::X509Validation => "X.509 Certificate Validation",
            Self::PkiInfrastructure => "PKI Infrastructure Assessment",
            Self::CertificateExpiration => "Certificate Expiration Monitoring",
            Self::CertificateChain => "Certificate Chain Validation",
            Self::CertificateRevocation => "Certificate Revocation (CRL/OCSP)",
            Self::SecureCertStorage => "Secure Certificate Storage",
            Self::CaCertManagement => "CA Certificate Management",
            Self::TlsCertValidation => "TLS Certificate Validation",
            Self::CertificateRotation => "Certificate Rotation Mechanisms",
            Self::ComplianceStandards => "Certificate Compliance Standards",
        }
    }

    fn category(&self) -> &str {
        "certificate"
    }

    fn description(&self) -> &str {
        match self {
            Self::X509Validation => "Verify X.509 certificate format and validation",
            Self::PkiInfrastructure => "Assess PKI infrastructure components and health",
            Self::CertificateExpiration => "Monitor certificate expiration dates and alerts",
            Self::CertificateChain => "Validate complete certificate trust chains",
            Self::CertificateRevocation => "Check CRL and OCSP revocation mechanisms",
            Self::SecureCertStorage => "Verify secure storage of private keys and certificates",
            Self::CaCertManagement => "Check CA certificate management and updates",
            Self::TlsCertValidation => "Validate TLS certificates for services",
            Self::CertificateRotation => "Verify certificate rotation and renewal processes",
            Self::ComplianceStandards => "Check compliance with certificate standards",
        }
    }
}

impl CertificateTests {
    async fn test_x509_validation(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check OpenSSL availability
        let openssl_check = target.execute_command("openssl version 2>/dev/null || echo 'no_openssl'").await?;
        
        if openssl_check.stdout.contains("no_openssl") {
            return Ok((TestStatus::Skipped, "OpenSSL not available for certificate validation".to_string(), None));
        }
        
        // Find system certificates
        let cert_locations = target.execute_command("find /etc/ssl /usr/share/ca-certificates /etc/pki -name '*.crt' -o -name '*.pem' 2>/dev/null | wc -l").await?;
        
        // Test certificate validation
        let cert_validation = target.execute_command("openssl x509 -in /etc/ssl/certs/ca-certificates.crt -text -noout 2>/dev/null | head -5 || echo 'validation_failed'").await?;
        
        let cert_count: usize = cert_locations.stdout.trim().parse().unwrap_or(0);
        
        let mut validation_features = Vec::new();
        
        if cert_count > 0 {
            validation_features.push("System certificates present");
        }
        if !cert_validation.stdout.contains("validation_failed") {
            validation_features.push("Certificate validation working");
        }
        
        let details = format!("OpenSSL: {}\nCertificate count: {}\nValidation test: {}", 
                             openssl_check.stdout.trim(), cert_count, 
                             if cert_validation.stdout.contains("validation_failed") { "Failed" } else { "Passed" });
        
        if validation_features.len() >= 2 {
            Ok((TestStatus::Passed, "X.509 validation infrastructure ready".to_string(), Some(details)))
        } else if validation_features.len() >= 1 {
            Ok((TestStatus::Warning, "Basic X.509 validation available".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "X.509 validation not available".to_string(), Some(details)))
        }
    }

    async fn test_pki_infrastructure(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for PKI directories
        let pki_dirs = target.execute_command("ls -la /etc/pki /usr/share/ca-certificates /etc/ssl 2>/dev/null | grep ^d | wc -l").await?;
        
        // Check CA bundle
        let ca_bundle = target.execute_command("ls -la /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt 2>/dev/null | wc -l").await?;
        
        // Check certificate stores
        let cert_stores = target.execute_command("update-ca-certificates --help 2>/dev/null || c_rehash --help 2>/dev/null || echo 'no_cert_tools'").await?;
        
        let pki_dir_count: usize = pki_dirs.stdout.trim().parse().unwrap_or(0);
        let ca_bundle_count: usize = ca_bundle.stdout.trim().parse().unwrap_or(0);
        
        let mut pki_features = Vec::new();
        
        if pki_dir_count >= 2 {
            pki_features.push("PKI directory structure");
        }
        if ca_bundle_count > 0 {
            pki_features.push("CA bundle present");
        }
        if !cert_stores.stdout.contains("no_cert_tools") {
            pki_features.push("Certificate management tools");
        }
        
        let details = format!("PKI directories: {}\nCA bundles: {}\nCert tools: {}", 
                             pki_dir_count, ca_bundle_count, 
                             if cert_stores.stdout.contains("no_cert_tools") { "None" } else { "Available" });
        
        if pki_features.len() >= 3 {
            Ok((TestStatus::Passed, "PKI infrastructure complete".to_string(), Some(details)))
        } else if pki_features.len() >= 2 {
            Ok((TestStatus::Warning, "Basic PKI infrastructure".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Insufficient PKI infrastructure".to_string(), Some(details)))
        }
    }

    async fn test_certificate_expiration(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check system certificates for expiration
        let cert_expiry = target.execute_command("find /etc/ssl/certs -name '*.pem' -exec openssl x509 -in {} -enddate -noout \\; 2>/dev/null | head -5 || echo 'no_cert_dates'").await?;
        
        // Check for certificate monitoring tools
        let monitoring_tools = target.execute_command("which certbot 2>/dev/null || which cert-manager 2>/dev/null || echo 'no_monitoring'").await?;
        
        // Check for automated renewal
        let renewal_check = target.execute_command("systemctl list-timers | grep -i cert || crontab -l 2>/dev/null | grep -i cert || echo 'no_renewal'").await?;
        
        let mut expiry_features = Vec::new();
        
        if !cert_expiry.stdout.contains("no_cert_dates") {
            expiry_features.push("Certificate expiry readable");
        }
        if !monitoring_tools.stdout.contains("no_monitoring") {
            expiry_features.push("Monitoring tools available");
        }
        if !renewal_check.stdout.contains("no_renewal") {
            expiry_features.push("Automated renewal configured");
        }
        
        let details = format!("Certificate dates: {}\nMonitoring: {}\nRenewal: {}", 
                             if cert_expiry.stdout.contains("no_cert_dates") { "Not available" } else { "Available" },
                             monitoring_tools.stdout.trim(),
                             if renewal_check.stdout.contains("no_renewal") { "Not configured" } else { "Configured" });
        
        if expiry_features.len() >= 3 {
            Ok((TestStatus::Passed, "Certificate expiration monitoring complete".to_string(), Some(details)))
        } else if expiry_features.len() >= 2 {
            Ok((TestStatus::Warning, "Basic expiration monitoring".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "No certificate expiration monitoring".to_string(), Some(details)))
        }
    }

    async fn test_certificate_chain(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Test certificate chain validation
        let chain_test = target.execute_command("openssl s_client -connect localhost:443 -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -subject 2>/dev/null || echo 'no_tls_service'").await?;
        
        // Check certificate chain files
        let chain_files = target.execute_command("find /etc/ssl -name '*chain*' -o -name '*intermediate*' 2>/dev/null | wc -l").await?;
        
        // Verify CA certificate validation
        let ca_verify = target.execute_command("openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt 2>/dev/null || echo 'verify_failed'").await?;
        
        let chain_file_count: usize = chain_files.stdout.trim().parse().unwrap_or(0);
        
        let mut chain_features = Vec::new();
        
        if !chain_test.stdout.contains("no_tls_service") {
            chain_features.push("TLS chain testable");
        }
        if chain_file_count > 0 {
            chain_features.push("Certificate chain files");
        }
        if ca_verify.stdout.contains("OK") {
            chain_features.push("CA verification working");
        }
        
        let details = format!("TLS test: {}\nChain files: {}\nCA verification: {}", 
                             if chain_test.stdout.contains("no_tls_service") { "No service" } else { "Available" },
                             chain_file_count,
                             if ca_verify.stdout.contains("OK") { "OK" } else { "Failed" });
        
        if chain_features.len() >= 2 {
            Ok((TestStatus::Passed, "Certificate chain validation working".to_string(), Some(details)))
        } else if chain_features.len() >= 1 {
            Ok((TestStatus::Warning, "Basic chain validation".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Certificate chain validation not working".to_string(), Some(details)))
        }
    }

    async fn test_certificate_revocation(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for CRL files
        let crl_files = target.execute_command("find /etc/ssl -name '*.crl' 2>/dev/null | wc -l").await?;
        
        // Check OCSP support
        let ocsp_check = target.execute_command("openssl ocsp -help 2>/dev/null | head -1 || echo 'no_ocsp'").await?;
        
        // Check for revocation checking in applications
        let app_revocation = target.execute_command("grep -r 'crl\\|ocsp\\|revocation' /etc/ssl /etc/nginx /etc/apache2 2>/dev/null | wc -l").await?;
        
        let crl_count: usize = crl_files.stdout.trim().parse().unwrap_or(0);
        let revocation_configs: usize = app_revocation.stdout.trim().parse().unwrap_or(0);
        
        let mut revocation_features = Vec::new();
        
        if crl_count > 0 {
            revocation_features.push("CRL files present");
        }
        if !ocsp_check.stdout.contains("no_ocsp") {
            revocation_features.push("OCSP support available");
        }
        if revocation_configs > 0 {
            revocation_features.push("Application revocation checking");
        }
        
        let details = format!("CRL files: {}\nOCSP support: {}\nApp configs: {}", 
                             crl_count,
                             if ocsp_check.stdout.contains("no_ocsp") { "Not available" } else { "Available" },
                             revocation_configs);
        
        if revocation_features.len() >= 2 {
            Ok((TestStatus::Passed, "Certificate revocation mechanisms active".to_string(), Some(details)))
        } else if revocation_features.len() >= 1 {
            Ok((TestStatus::Warning, "Basic revocation support".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "No certificate revocation checking".to_string(), Some(details)))
        }
    }

    async fn test_secure_cert_storage(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check private key permissions
        let key_permissions = target.execute_command("find /etc/ssl/private -type f -exec ls -la {} \\; 2>/dev/null | grep -E '^-r--------' | wc -l").await?;
        
        // Check certificate directory permissions
        let cert_dir_perms = target.execute_command("ls -la /etc/ssl/private /etc/pki/tls/private 2>/dev/null | grep ^d | grep -E 'rwx------' | wc -l").await?;
        
        // Check for hardware security modules
        let hsm_check = target.execute_command("ls /dev/tpm* 2>/dev/null || find /usr -name '*pkcs11*' 2>/dev/null | head -3 || echo 'no_hsm'").await?;
        
        let secure_keys: usize = key_permissions.stdout.trim().parse().unwrap_or(0);
        let secure_dirs: usize = cert_dir_perms.stdout.trim().parse().unwrap_or(0);
        
        let mut storage_features = Vec::new();
        
        if secure_keys > 0 {
            storage_features.push("Secure private key permissions");
        }
        if secure_dirs > 0 {
            storage_features.push("Secure certificate directories");
        }
        if !hsm_check.stdout.contains("no_hsm") {
            storage_features.push("Hardware security support");
        }
        
        let details = format!("Secure keys: {}\nSecure dirs: {}\nHSM support: {}", 
                             secure_keys, secure_dirs,
                             if hsm_check.stdout.contains("no_hsm") { "Not available" } else { "Available" });
        
        if storage_features.len() >= 2 {
            Ok((TestStatus::Passed, "Certificate storage security good".to_string(), Some(details)))
        } else if storage_features.len() >= 1 {
            Ok((TestStatus::Warning, "Basic storage security".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Poor certificate storage security".to_string(), Some(details)))
        }
    }

    async fn test_ca_cert_management(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check CA certificate count
        let ca_count = target.execute_command("grep -c 'BEGIN CERTIFICATE' /etc/ssl/certs/ca-certificates.crt 2>/dev/null || echo '0'").await?;
        
        // Check CA update mechanism
        let ca_update = target.execute_command("which update-ca-certificates 2>/dev/null || which ca-certificates-update 2>/dev/null || echo 'no_update'").await?;
        
        // Check CA certificate validity
        let ca_validity = target.execute_command("openssl x509 -in /etc/ssl/certs/ca-certificates.crt -enddate -noout 2>/dev/null | head -1 || echo 'no_validity'").await?;
        
        let ca_cert_count: usize = ca_count.stdout.trim().parse().unwrap_or(0);
        
        let mut ca_features = Vec::new();
        
        if ca_cert_count > 100 {
            ca_features.push("Comprehensive CA bundle");
        }
        if !ca_update.stdout.contains("no_update") {
            ca_features.push("CA update tools available");
        }
        if !ca_validity.stdout.contains("no_validity") {
            ca_features.push("CA certificate validity checkable");
        }
        
        let details = format!("CA certificates: {}\nUpdate tools: {}\nValidity check: {}", 
                             ca_cert_count,
                             if ca_update.stdout.contains("no_update") { "Not available" } else { "Available" },
                             if ca_validity.stdout.contains("no_validity") { "Not available" } else { "Available" });
        
        if ca_features.len() >= 3 {
            Ok((TestStatus::Passed, "CA certificate management complete".to_string(), Some(details)))
        } else if ca_features.len() >= 2 {
            Ok((TestStatus::Warning, "Basic CA management".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Poor CA certificate management".to_string(), Some(details)))
        }
    }

    async fn test_tls_cert_validation(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for TLS services
        let tls_services = target.execute_command("netstat -tuln | grep ':443\\|:993\\|:995\\|:636' | wc -l").await?;
        
        // Test TLS certificate validation
        let tls_test = target.execute_command("echo | openssl s_client -connect localhost:443 -verify_return_error 2>/dev/null | grep -E 'Verify return code|subject=' || echo 'no_tls_test'").await?;
        
        // Check TLS configuration files
        let tls_configs = target.execute_command("find /etc -name '*.conf' -exec grep -l 'ssl\\|tls\\|certificate' {} \\; 2>/dev/null | wc -l").await?;
        
        let service_count: usize = tls_services.stdout.trim().parse().unwrap_or(0);
        let config_count: usize = tls_configs.stdout.trim().parse().unwrap_or(0);
        
        let mut tls_features = Vec::new();
        
        if service_count > 0 {
            tls_features.push("TLS services running");
        }
        if !tls_test.stdout.contains("no_tls_test") {
            tls_features.push("TLS validation testable");
        }
        if config_count > 0 {
            tls_features.push("TLS configurations present");
        }
        
        let details = format!("TLS services: {}\nValidation test: {}\nConfigurations: {}", 
                             service_count,
                             if tls_test.stdout.contains("no_tls_test") { "Not available" } else { "Available" },
                             config_count);
        
        if tls_features.len() >= 2 {
            Ok((TestStatus::Passed, "TLS certificate validation working".to_string(), Some(details)))
        } else if tls_features.len() >= 1 {
            Ok((TestStatus::Warning, "Basic TLS validation".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "TLS certificate validation not available".to_string(), Some(details)))
        }
    }

    async fn test_certificate_rotation(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for automated certificate renewal
        let renewal_services = target.execute_command("systemctl list-units --type=service | grep -E 'certbot|cert-manager|acme' || echo 'no_renewal_services'").await?;
        
        // Check for certificate rotation scripts
        let rotation_scripts = target.execute_command("find /etc/cron.d /etc/cron.daily /etc/cron.weekly -name '*cert*' 2>/dev/null | wc -l").await?;
        
        // Check for certificate backup/restore
        let backup_check = target.execute_command("find /etc -name '*backup*' -path '*/ssl/*' -o -name '*backup*' -path '*/pki/*' 2>/dev/null | wc -l").await?;
        
        let script_count: usize = rotation_scripts.stdout.trim().parse().unwrap_or(0);
        let backup_count: usize = backup_check.stdout.trim().parse().unwrap_or(0);
        
        let mut rotation_features = Vec::new();
        
        if !renewal_services.stdout.contains("no_renewal_services") {
            rotation_features.push("Renewal services available");
        }
        if script_count > 0 {
            rotation_features.push("Rotation scripts configured");
        }
        if backup_count > 0 {
            rotation_features.push("Certificate backup mechanisms");
        }
        
        let details = format!("Renewal services: {}\nRotation scripts: {}\nBackup mechanisms: {}", 
                             if renewal_services.stdout.contains("no_renewal_services") { "None" } else { "Available" },
                             script_count, backup_count);
        
        if rotation_features.len() >= 2 {
            Ok((TestStatus::Passed, "Certificate rotation mechanisms active".to_string(), Some(details)))
        } else if rotation_features.len() >= 1 {
            Ok((TestStatus::Warning, "Basic rotation support".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "No certificate rotation mechanisms".to_string(), Some(details)))
        }
    }

    async fn test_compliance_standards(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check certificate key lengths
        let key_lengths = target.execute_command("find /etc/ssl/certs -name '*.pem' -exec openssl x509 -in {} -text -noout \\; 2>/dev/null | grep -E 'Public-Key:|RSA Public-Key:' | head -5 || echo 'no_key_info'").await?;
        
        // Check signature algorithms
        let sig_algorithms = target.execute_command("find /etc/ssl/certs -name '*.pem' -exec openssl x509 -in {} -text -noout \\; 2>/dev/null | grep 'Signature Algorithm:' | sort | uniq -c || echo 'no_sig_info'").await?;
        
        // Check certificate validity periods
        let validity_periods = target.execute_command("find /etc/ssl/certs -name '*.pem' -exec openssl x509 -in {} -dates -noout \\; 2>/dev/null | head -10 || echo 'no_validity_info'").await?;
        
        let mut compliance_features = Vec::new();
        
        if key_lengths.stdout.contains("2048 bit") || key_lengths.stdout.contains("4096 bit") {
            compliance_features.push("Adequate key lengths");
        }
        if sig_algorithms.stdout.contains("sha256") && !sig_algorithms.stdout.contains("sha1") {
            compliance_features.push("Modern signature algorithms");
        }
        if !validity_periods.stdout.contains("no_validity_info") {
            compliance_features.push("Certificate validity tracking");
        }
        
        let details = format!("Key lengths: {}\nSignature algorithms: {}\nValidity periods: {}", 
                             if key_lengths.stdout.contains("no_key_info") { "Not available" } else { "Available" },
                             if sig_algorithms.stdout.contains("no_sig_info") { "Not available" } else { "Available" },
                             if validity_periods.stdout.contains("no_validity_info") { "Not available" } else { "Available" });
        
        if compliance_features.len() >= 3 {
            Ok((TestStatus::Passed, "Certificate compliance standards met".to_string(), Some(details)))
        } else if compliance_features.len() >= 2 {
            Ok((TestStatus::Warning, "Basic compliance standards".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Certificate compliance standards not met".to_string(), Some(details)))
        }
    }
}
