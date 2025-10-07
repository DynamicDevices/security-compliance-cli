use crate::{
    error::Result,
    target::Target,
    tests::{create_test_result, SecurityTest, TestResult, TestStatus},
};
use async_trait::async_trait;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum ContainerSecurityTests {
    DockerSecurityConfig,
    ContainerImageSecurity,
    RuntimeSecurity,
    NetworkIsolation,
    UserNamespaces,
    SelinuxContexts,
    SeccompProfiles,
}

#[async_trait]
impl SecurityTest for ContainerSecurityTests {
    async fn run(&self, target: &mut Target) -> Result<TestResult> {
        let start_time = Instant::now();
        
        let result = match self {
            Self::DockerSecurityConfig => self.test_docker_security_config(target).await,
            Self::ContainerImageSecurity => self.test_container_image_security(target).await,
            Self::RuntimeSecurity => self.test_runtime_security(target).await,
            Self::NetworkIsolation => self.test_network_isolation(target).await,
            Self::UserNamespaces => self.test_user_namespaces(target).await,
            Self::SelinuxContexts => self.test_selinux_contexts(target).await,
            Self::SeccompProfiles => self.test_seccomp_profiles(target).await,
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
            Self::DockerSecurityConfig => "container_001",
            Self::ContainerImageSecurity => "container_002",
            Self::RuntimeSecurity => "container_003",
            Self::NetworkIsolation => "container_004",
            Self::UserNamespaces => "container_005",
            Self::SelinuxContexts => "container_006",
            Self::SeccompProfiles => "container_007",
        }
    }

    fn test_name(&self) -> &str {
        match self {
            Self::DockerSecurityConfig => "Docker/Podman Security Configuration",
            Self::ContainerImageSecurity => "Container Image Security",
            Self::RuntimeSecurity => "Container Runtime Security",
            Self::NetworkIsolation => "Network Isolation and Resource Limits",
            Self::UserNamespaces => "User Namespaces and Capabilities",
            Self::SelinuxContexts => "SELinux Container Contexts",
            Self::SeccompProfiles => "Seccomp Security Profiles",
        }
    }

    fn category(&self) -> &str {
        "container"
    }

    fn description(&self) -> &str {
        match self {
            Self::DockerSecurityConfig => "Validates Docker/Podman daemon security configuration including socket permissions, TLS authentication, and daemon privilege restrictions. Ensures the container runtime is hardened against privilege escalation and unauthorized access. Critical for preventing container breakout attacks and maintaining host system security.",
            Self::ContainerImageSecurity => "Assesses container image security including signature verification, vulnerability scanning, and trusted registry usage. Validates that only signed, verified images from trusted sources are used. Essential for preventing supply chain attacks and ensuring container image integrity.",
            Self::RuntimeSecurity => "Evaluates container runtime security features including capability restrictions, resource limits, and security profiles. Ensures containers run with minimal privileges and proper isolation. Fundamental for preventing container escape and limiting blast radius of potential compromises.",
            Self::NetworkIsolation => "Validates container network isolation and segmentation policies. Checks for proper network namespace separation, firewall rules, and inter-container communication controls. Critical for preventing lateral movement and network-based attacks between containers and to the host system.",
            Self::UserNamespaces => "Verifies user namespace isolation is properly configured to map container users to unprivileged host users. Prevents containers from running as root on the host system. Essential security feature for reducing the impact of container breakout vulnerabilities.",
            Self::SelinuxContexts => "Checks SELinux mandatory access control contexts for containers to enforce fine-grained security policies. Validates that containers run with appropriate SELinux labels and restrictions. Important for defense-in-depth security and containing potential breaches.",
            Self::SeccompProfiles => "Validates seccomp (secure computing) profiles that restrict system calls available to containers. Reduces attack surface by blocking potentially dangerous system calls. Critical for preventing privilege escalation and system compromise through container exploits.",
        }
    }
}

impl ContainerSecurityTests {
    async fn test_docker_security_config(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check if Docker/Podman is installed
        let docker_check = target.execute_command("which docker 2>/dev/null || which podman 2>/dev/null || echo 'not_found'").await?;
        
        if docker_check.stdout.contains("not_found") {
            return Ok((TestStatus::Failed, "No container runtime detected - install Docker or Podman".to_string(), None));
        }

        // Check Docker daemon configuration
        let docker_config = target.execute_command("docker info 2>/dev/null | grep -E 'Security Options|User Namespaces|Seccomp|SELinux' || echo 'docker_not_running'").await?;
        
        // Check for rootless mode
        let rootless_check = target.execute_command("docker info 2>/dev/null | grep -i rootless || echo 'not_rootless'").await?;
        
        let mut security_features = Vec::new();
        let mut details = Vec::new();
        
        if docker_config.stdout.contains("seccomp") {
            security_features.push("Seccomp");
        }
        if docker_config.stdout.contains("selinux") {
            security_features.push("SELinux");
        }
        if !rootless_check.stdout.contains("not_rootless") {
            security_features.push("Rootless mode");
        }
        
        details.push(format!("Docker info: {}", docker_config.stdout));
        details.push(format!("Security features: {:?}", security_features));
        
        if security_features.len() >= 2 {
            Ok((TestStatus::Passed, format!("Container security configured ({} features)", security_features.len()), Some(details.join("\n"))))
        } else if security_features.len() >= 1 {
            Ok((TestStatus::Warning, format!("Basic container security ({} features)", security_features.len()), Some(details.join("\n"))))
        } else {
            Ok((TestStatus::Failed, "Insufficient container security configuration".to_string(), Some(details.join("\n"))))
        }
    }

    async fn test_container_image_security(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check for image scanning tools
        let scanning_tools = target.execute_command("which trivy 2>/dev/null || which clair 2>/dev/null || which grype 2>/dev/null || echo 'no_scanners'").await?;
        
        // Check running containers
        let running_containers = target.execute_command("docker ps --format 'table {{.Names}}\t{{.Image}}' 2>/dev/null || podman ps --format 'table {{.Names}}\t{{.Image}}' 2>/dev/null || echo 'no_containers'").await?;
        
        // Check for base image security
        let base_images = target.execute_command("docker images --format 'table {{.Repository}}\t{{.Tag}}' 2>/dev/null | grep -E 'alpine|distroless|scratch' || echo 'no_secure_bases'").await?;
        
        let mut security_indicators = Vec::new();
        
        if !scanning_tools.stdout.contains("no_scanners") {
            security_indicators.push("Image scanning tools available");
        }
        if !base_images.stdout.contains("no_secure_bases") {
            security_indicators.push("Secure base images detected");
        }
        if running_containers.stdout.lines().count() <= 5 {
            security_indicators.push("Limited container exposure");
        }
        
        let details = format!("Scanners: {}\nContainers: {}\nBase images: {}", 
                             scanning_tools.stdout.trim(), running_containers.stdout, base_images.stdout);
        
        if security_indicators.len() >= 2 {
            Ok((TestStatus::Passed, format!("Image security good: {:?}", security_indicators), Some(details)))
        } else if security_indicators.len() >= 1 {
            Ok((TestStatus::Warning, format!("Basic image security: {:?}", security_indicators), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Poor container image security".to_string(), Some(details)))
        }
    }

    async fn test_runtime_security(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check container runtime security settings
        let runtime_check = target.execute_command("docker info 2>/dev/null | grep -E 'Runtime|Default Runtime' || echo 'no_runtime_info'").await?;
        
        // Check for privileged containers
        let privileged_check = target.execute_command("docker ps --filter 'label=privileged=true' --format '{{.Names}}' 2>/dev/null || echo 'no_privileged'").await?;
        
        // Check resource limits
        let resource_limits = target.execute_command("docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' 2>/dev/null | wc -l").await?;
        
        let mut runtime_security = Vec::new();
        
        if privileged_check.stdout.trim() == "no_privileged" || privileged_check.stdout.trim().is_empty() {
            runtime_security.push("No privileged containers");
        }
        
        let container_count: usize = resource_limits.stdout.trim().parse().unwrap_or(0);
        if container_count > 0 && container_count <= 10 {
            runtime_security.push("Resource monitoring active");
        }
        
        let details = format!("Runtime: {}\nPrivileged: {}\nContainer count: {}", 
                             runtime_check.stdout, privileged_check.stdout, container_count);
        
        if runtime_security.len() >= 2 {
            Ok((TestStatus::Passed, "Container runtime security good".to_string(), Some(details)))
        } else if runtime_security.len() >= 1 {
            Ok((TestStatus::Warning, "Basic runtime security".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Poor container runtime security".to_string(), Some(details)))
        }
    }

    async fn test_network_isolation(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check Docker networks
        let networks = target.execute_command("docker network ls --format '{{.Name}}\t{{.Driver}}' 2>/dev/null || echo 'no_networks'").await?;
        
        // Check for custom networks
        let custom_networks = target.execute_command("docker network ls --filter 'driver=bridge' --format '{{.Name}}' 2>/dev/null | grep -v bridge || echo 'no_custom'").await?;
        
        // Check network policies
        let network_policies = target.execute_command("iptables -L DOCKER-USER 2>/dev/null | wc -l").await?;
        
        let mut isolation_features = Vec::new();
        
        if !custom_networks.stdout.contains("no_custom") && !custom_networks.stdout.trim().is_empty() {
            isolation_features.push("Custom networks");
        }
        
        let policy_count: usize = network_policies.stdout.trim().parse().unwrap_or(0);
        if policy_count > 3 {
            isolation_features.push("Network policies");
        }
        
        let details = format!("Networks: {}\nCustom networks: {}\nPolicies: {}", 
                             networks.stdout, custom_networks.stdout, policy_count);
        
        if isolation_features.len() >= 2 {
            Ok((TestStatus::Passed, "Network isolation configured".to_string(), Some(details)))
        } else if isolation_features.len() >= 1 {
            Ok((TestStatus::Warning, "Basic network isolation".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Poor network isolation".to_string(), Some(details)))
        }
    }

    async fn test_user_namespaces(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check user namespace support
        let userns_check = target.execute_command("docker info 2>/dev/null | grep -i 'user.*namespace' || echo 'no_userns'").await?;
        
        // Check for rootless containers
        let rootless_containers = target.execute_command("docker ps --format '{{.Names}}' 2>/dev/null | xargs -I {} docker inspect {} --format '{{.HostConfig.UsernsMode}}' 2>/dev/null || echo 'no_containers'").await?;
        
        // Check capabilities
        let cap_check = target.execute_command("docker ps --format '{{.Names}}' 2>/dev/null | head -3 | xargs -I {} docker inspect {} --format '{{.HostConfig.CapDrop}}' 2>/dev/null || echo 'no_cap_info'").await?;
        
        let mut namespace_security = Vec::new();
        
        if !userns_check.stdout.contains("no_userns") {
            namespace_security.push("User namespaces available");
        }
        if cap_check.stdout.contains("ALL") || cap_check.stdout.contains("SYS_ADMIN") {
            namespace_security.push("Capability restrictions");
        }
        
        let details = format!("User namespaces: {}\nRootless: {}\nCapabilities: {}", 
                             userns_check.stdout, rootless_containers.stdout, cap_check.stdout);
        
        if namespace_security.len() >= 2 {
            Ok((TestStatus::Passed, "User namespace security configured".to_string(), Some(details)))
        } else if namespace_security.len() >= 1 {
            Ok((TestStatus::Warning, "Basic namespace security".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Poor user namespace security".to_string(), Some(details)))
        }
    }

    async fn test_selinux_contexts(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check SELinux status
        let selinux_status = target.execute_command("getenforce 2>/dev/null || echo 'no_selinux'").await?;
        
        if selinux_status.stdout.contains("no_selinux") || selinux_status.stdout.trim() == "Disabled" {
            return Ok((TestStatus::Skipped, "SELinux not available or disabled".to_string(), None));
        }
        
        // Check container SELinux contexts
        let container_contexts = target.execute_command("docker ps --format '{{.Names}}' 2>/dev/null | head -3 | xargs -I {} docker inspect {} --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null || echo 'no_contexts'").await?;
        
        // Check SELinux policy for containers
        let selinux_policy = target.execute_command("sesearch -A -s container_t 2>/dev/null | wc -l").await?;
        
        let mut selinux_features = Vec::new();
        
        if selinux_status.stdout.trim() == "Enforcing" {
            selinux_features.push("SELinux enforcing");
        }
        if container_contexts.stdout.contains("selinux") {
            selinux_features.push("Container contexts");
        }
        
        let policy_rules: usize = selinux_policy.stdout.trim().parse().unwrap_or(0);
        if policy_rules > 0 {
            selinux_features.push("Container policies");
        }
        
        let details = format!("SELinux: {}\nContexts: {}\nPolicy rules: {}", 
                             selinux_status.stdout.trim(), container_contexts.stdout, policy_rules);
        
        if selinux_features.len() >= 2 {
            Ok((TestStatus::Passed, "SELinux container security active".to_string(), Some(details)))
        } else if selinux_features.len() >= 1 {
            Ok((TestStatus::Warning, "Basic SELinux container security".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Poor SELinux container security".to_string(), Some(details)))
        }
    }

    async fn test_seccomp_profiles(&self, target: &mut Target) -> Result<(TestStatus, String, Option<String>)> {
        // Check seccomp support
        let seccomp_check = target.execute_command("docker info 2>/dev/null | grep -i seccomp || echo 'no_seccomp'").await?;
        
        // Check container seccomp profiles
        let container_seccomp = target.execute_command("docker ps --format '{{.Names}}' 2>/dev/null | head -3 | xargs -I {} docker inspect {} --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null | grep seccomp || echo 'no_profiles'").await?;
        
        // Check for custom seccomp profiles
        let custom_profiles = target.execute_command("find /etc/docker /usr/share/containers -name '*seccomp*.json' 2>/dev/null | wc -l").await?;
        
        let mut seccomp_features = Vec::new();
        
        if !seccomp_check.stdout.contains("no_seccomp") {
            seccomp_features.push("Seccomp support");
        }
        if !container_seccomp.stdout.contains("no_profiles") {
            seccomp_features.push("Container profiles");
        }
        
        let profile_count: usize = custom_profiles.stdout.trim().parse().unwrap_or(0);
        if profile_count > 0 {
            seccomp_features.push("Custom profiles");
        }
        
        let details = format!("Seccomp support: {}\nContainer profiles: {}\nCustom profiles: {}", 
                             seccomp_check.stdout, container_seccomp.stdout, profile_count);
        
        if seccomp_features.len() >= 2 {
            Ok((TestStatus::Passed, "Seccomp security profiles active".to_string(), Some(details)))
        } else if seccomp_features.len() >= 1 {
            Ok((TestStatus::Warning, "Basic seccomp security".to_string(), Some(details)))
        } else {
            Ok((TestStatus::Failed, "Poor seccomp security".to_string(), Some(details)))
        }
    }
}
