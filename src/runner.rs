/*
 * Security Compliance CLI - Test Runner
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::{
    cli::{TestMode, TestSuite},
    config::OutputConfig,
    error::Result,
    output::OutputHandler,
    target::Target,
    tests::{SecurityTest, TestRegistry, TestSuiteResults, TestStatus},
};
use chrono::Utc;
use std::time::Instant;
use tracing::{info, error};

pub struct TestRunner {
    target: Target,
    output_handler: OutputHandler,
    registry: TestRegistry,
    test_mode: TestMode,
    verbose: u8,
}

impl TestRunner {
    pub fn new(target: Target, output_config: OutputConfig, test_mode: TestMode) -> Result<Self> {
        let verbose = output_config.verbose;
        let output_handler = OutputHandler::new(output_config)?;
        let registry = TestRegistry::new();
        
        Ok(Self {
            target,
            output_handler,
            registry,
            test_mode,
            verbose,
        })
    }

    pub async fn run_tests(&mut self, test_suite: &TestSuite) -> Result<TestSuiteResults> {
        info!("Starting security compliance test suite: {:?} in {:?} mode", test_suite, self.test_mode);
        
        let start_time = Instant::now();
        
        // Connect to target
        self.target.connect().await?;
        
        // Get system information
        let system_info = self.target.get_system_info().await?;
        info!("Target system: {}", system_info.uname);
        
        // Get tests for the suite, filtered by mode
        let test_ids = self.registry.get_tests_for_suite_and_mode(test_suite, &self.test_mode);
        info!("Running {} tests", test_ids.len());
        
        let mut results = Vec::new();
        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;
        let mut skipped = 0;
        let mut errors = 0;
        
        // Initialize progress reporting
        self.output_handler.start_test_suite(&format!("{:?}", test_suite), test_ids.len()).await?;
        
        // Run each test
        for (index, test_id) in test_ids.iter().enumerate() {
            if let Some(test) = self.registry.get_test(test_id) {
                if self.verbose > 0 {
                    info!("Running test {}/{}: {} - {}", index + 1, test_ids.len(), test.test_id(), test.test_name());
                    info!("📋 Purpose: {}", test.description());
                    if self.verbose > 1 {
                        info!("🏷️  Category: {}", test.category());
                    }
                } else {
                    info!("Running test {}/{}: {} - {}", index + 1, test_ids.len(), test.test_id(), test.test_name());
                }
                
                self.output_handler.start_test(test.test_id(), test.test_name()).await?;
                
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
        self.output_handler.complete_test_suite(&suite_results).await?;
        
        info!("Test suite completed in {:?}", duration);
        info!("Results: {} passed, {} failed, {} warnings, {} skipped, {} errors", 
              passed, failed, warnings, skipped, errors);
        
        Ok(suite_results)
    }
}
