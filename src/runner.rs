/*
 * Security Compliance CLI - Test Runner
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::{
    cli::{TestMode, TestSuite},
    config::{MachineConfig, OutputConfig},
    error::Result,
    machine::filter_tests_for_machine,
    output::OutputHandler,
    ssh_key::SshKeyInstaller,
    target::Target,
    tests::{SecurityTest, TestRegistry, TestStatus, TestSuiteResults},
};
use chrono::Utc;
use std::time::Instant;
use tracing::{error, info, warn};

pub struct TestRunner {
    target: Target,
    output_handler: OutputHandler,
    registry: TestRegistry,
    test_mode: TestMode,
    verbose: u8,
    machine_config: Option<MachineConfig>,
}

impl TestRunner {
    pub fn new(
        target: Target,
        output_config: OutputConfig,
        test_mode: TestMode,
        machine_config: Option<MachineConfig>,
    ) -> Result<Self> {
        let verbose = output_config.verbose;
        let output_handler = OutputHandler::new(output_config)?;
        let registry = TestRegistry::new();

        Ok(Self {
            target,
            output_handler,
            registry,
            test_mode,
            verbose,
            machine_config,
        })
    }

    pub async fn run_tests(&mut self, test_suite: &TestSuite) -> Result<TestSuiteResults> {
        info!(
            "Starting security compliance test suite: {:?} in {:?} mode",
            test_suite, self.test_mode
        );

        let start_time = Instant::now();

        // Connect to target
        self.target.connect().await?;

        // Get system information
        let system_info = self.target.get_system_info().await?;
        info!("Target system: {}", system_info.kernel_version);

        // Get tests for the suite, filtered by mode
        let test_ids_raw = self
            .registry
            .get_tests_for_suite_and_mode(test_suite, &self.test_mode);

        // Convert to Vec<String> for machine filtering
        let test_ids_strings: Vec<String> = test_ids_raw.iter().map(|s| s.to_string()).collect();

        // Apply machine-specific filtering
        let filtered_test_ids = filter_tests_for_machine(&test_ids_strings, &self.machine_config);

        // Convert back to Vec<&str> for compatibility with existing code
        let test_ids: Vec<&str> = test_ids_raw
            .into_iter()
            .filter(|id| filtered_test_ids.contains(&id.to_string()))
            .collect();

        if let Some(machine_config) = &self.machine_config {
            if !machine_config.auto_detect || machine_config.machine_type != "auto" {
                info!(
                    "🎯 Filtered tests for machine: {}",
                    machine_config.machine_type
                );
                if !machine_config.hardware_features.is_empty() {
                    info!(
                        "🔧 Hardware features: {}",
                        machine_config.hardware_features.join(", ")
                    );
                }
            }
        }

        info!("Running {} tests", test_ids.len());

        let mut results = Vec::new();
        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;
        let mut skipped = 0;
        let mut errors = 0;

        // Initialize progress reporting
        self.output_handler
            .start_test_suite(&format!("{:?}", test_suite), test_ids.len())
            .await?;

        // Run each test
        for (index, test_id) in test_ids.iter().enumerate() {
            if let Some(test) = self.registry.get_test(test_id) {
                if self.verbose > 0 {
                    info!(
                        "Running test {}/{}: {} - {}",
                        index + 1,
                        test_ids.len(),
                        test.test_id(),
                        test.test_name()
                    );
                    info!("📋 Purpose: {}", test.description());
                    if self.verbose > 1 {
                        info!("🏷️  Category: {}", test.category());
                    }
                } else {
                    info!(
                        "Running test {}/{}: {} - {}",
                        index + 1,
                        test_ids.len(),
                        test.test_id(),
                        test.test_name()
                    );
                }

                self.output_handler
                    .start_test(test.test_id(), test.test_name())
                    .await?;

                let result = test.run(&mut self.target).await?;

                match result.status {
                    TestStatus::Passed => {
                        passed += 1;
                    }
                    TestStatus::Failed => {
                        failed += 1;
                    }
                    TestStatus::Warning => {
                        warnings += 1;
                    }
                    TestStatus::Skipped => {
                        skipped += 1;
                    }
                    TestStatus::Error => {
                        errors += 1;
                    }
                }

                self.output_handler.complete_test(&result).await?;
                results.push(result);
            } else {
                error!("Test not found: {}", test_id);
            }
        }

        // Disconnect from target
        self.target.disconnect().await?;

        let duration = start_time.elapsed();

        let suite_results = TestSuiteResults {
            suite_name: format!("{:?}", test_suite),
            test_mode: format!("{:?}", self.test_mode),
            total_tests: test_ids.len(),
            passed,
            failed,
            warnings,
            skipped,
            errors,
            duration,
            timestamp: Utc::now(),
            system_info,
            results,
        };

        // Complete test suite reporting
        self.output_handler
            .complete_test_suite(&suite_results)
            .await?;

        // Check for remaining test keys and warn user
        self.check_for_remaining_test_keys().await;

        info!("Test suite completed in {:?}", duration);
        info!(
            "Results: {} passed, {} failed, {} warnings, {} skipped, {} errors",
            passed, failed, warnings, skipped, errors
        );

        Ok(suite_results)
    }

    /// Check if temporary test keys remain on the device and warn the user
    async fn check_for_remaining_test_keys(&mut self) {
        // Determine the target user - try to get from the current connection
        let target_user = if let Some(_machine_config) = &self.machine_config {
            // Try to get user from machine config or use default
            "root".to_string() // Default for most embedded systems
        } else {
            "root".to_string()
        };

        let installer = SshKeyInstaller::new(target_user.clone(), false);
        let comm_channel = self.target.get_communication_channel();

        match installer.detect_temp_keys(comm_channel).await {
            Ok(temp_keys) => {
                if !temp_keys.is_empty() {
                    warn!(
                        "⚠️  SECURITY WARNING: {} temporary test keys remain on the device!",
                        temp_keys.len()
                    );
                    warn!("🔑 These keys may allow unauthorized access to the device:");

                    for (i, key) in temp_keys.iter().enumerate() {
                        let display_key = installer.truncate_key_for_display(key);
                        warn!("   {}. {}", i + 1, display_key);
                    }

                    warn!("🧹 To remove all temporary keys, run:");
                    warn!("   security-compliance-cli uninstall-ssh-key --remove-temp-keys --target-user {}", target_user);
                    warn!("");
                    warn!("💡 For security, consider removing these keys before deploying to production!");
                } else {
                    info!("✅ No temporary test keys detected on device");
                }
            }
            Err(e) => {
                // Don't fail the entire test run if we can't check for keys
                warn!("⚠️  Could not check for remaining test keys: {}", e);
                warn!("💡 Manually verify no test keys remain: cat ~/.ssh/authorized_keys");
            }
        }
    }
}
