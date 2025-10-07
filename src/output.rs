use crate::{
    compliance::{
        format_compliance_report_as_markdown, generate_pdf_report, CraComplianceReporter,
        RedComplianceReporter,
    },
    config::OutputConfig,
    error::Result,
    tests::{TestResult, TestStatus, TestSuiteResults},
};
use chrono::Utc;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json;
use std::fs;

pub struct OutputHandler {
    config: OutputConfig,
    progress_bar: Option<ProgressBar>,
    current_test: usize,
    total_tests: usize,
}

impl OutputHandler {
    pub fn new(config: OutputConfig) -> Result<Self> {
        Ok(Self {
            config,
            progress_bar: None,
            current_test: 0,
            total_tests: 0,
        })
    }

    pub async fn start_test_suite(&mut self, suite_name: &str, total_tests: usize) -> Result<()> {
        self.total_tests = total_tests;
        self.current_test = 0;

        match self.config.format.as_str() {
            "human" => {
                println!("{}", "🔒 Security Compliance Testing".bold().blue());
                println!("{}", "================================".blue());
                println!("Suite: {}", suite_name.bold());
                println!("Tests: {}", total_tests);
                println!();

                if self.config.verbose == 0 {
                    let pb = ProgressBar::new(total_tests as u64);
                    pb.set_style(
                        ProgressStyle::default_bar()
                            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                            .unwrap()
                            .progress_chars("#>-"),
                    );
                    self.progress_bar = Some(pb);
                }
            }
            "json" => {
                // JSON output will be at the end
            }
            "junit" => {
                // JUnit XML will be at the end
            }
            "markdown" => {
                println!("# Security Compliance Test Report");
                println!();
                println!("**Suite:** {}", suite_name);
                println!("**Tests:** {}", total_tests);
                println!(
                    "**Started:** {}",
                    Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!();
            }
            "cra" | "red" | "pdf" => {
                // Compliance reports will be generated at the end
            }
            _ => {}
        }

        Ok(())
    }

    pub async fn start_test(&mut self, test_id: &str, test_name: &str) -> Result<()> {
        self.current_test += 1;

        if self.config.format.as_str() == "human" {
            if let Some(pb) = &self.progress_bar {
                pb.set_message(format!("{}: {}", test_id, test_name));
                pb.set_position(self.current_test as u64);
            } else if self.config.verbose > 0 {
                println!(
                    "🔍 [{}/{}] Running: {} - {}",
                    self.current_test, self.total_tests, test_id, test_name
                );
            }
        }

        Ok(())
    }

    pub async fn complete_test(&mut self, result: &TestResult) -> Result<()> {
        if self.config.format.as_str() == "human"
            && (self.progress_bar.is_none() || self.config.verbose > 0)
        {
            let status_icon = match result.status {
                TestStatus::Passed => "✅".green(),
                TestStatus::Failed => "❌".red(),
                TestStatus::Warning => "⚠️ ".yellow(),
                TestStatus::Skipped => "⏭️ ".blue(),
                TestStatus::Error => "💥".red(),
            };

            println!(
                "{} {} - {}: {}",
                status_icon, result.test_id, result.test_name, result.message
            );

            if self.config.verbose > 1 && result.details.is_some() {
                println!("   Details: {}", result.details.as_ref().unwrap());
            }
        }

        Ok(())
    }

    pub async fn complete_test_suite(&mut self, results: &TestSuiteResults) -> Result<()> {
        if let Some(pb) = &self.progress_bar {
            pb.finish_with_message("Tests completed");
            println!();
        }

        match self.config.format.as_str() {
            "human" => self.output_human_summary(results).await?,
            "json" => self.output_json(results).await?,
            "junit" => self.output_junit(results).await?,
            "markdown" => self.output_markdown(results).await?,
            "cra" => self.output_cra_compliance(results).await?,
            "red" => self.output_red_compliance(results).await?,
            "pdf" => self.output_pdf_report(results).await?,
            _ => {}
        }

        // Write to file if specified
        if let Some(output_file) = &self.config.file {
            self.write_to_file(results, output_file).await?;
        }

        Ok(())
    }

    async fn output_human_summary(&self, results: &TestSuiteResults) -> Result<()> {
        println!("{}", "📊 Test Results Summary".bold().blue());
        println!("{}", "======================".blue());
        println!();

        // Overall status
        let overall_status = if results.overall_passed() {
            "PASSED".green().bold()
        } else {
            "FAILED".red().bold()
        };
        println!("Overall Status: {}", overall_status);
        println!("Success Rate: {:.1}%", results.success_rate());
        println!("Test Mode: {}", results.test_mode);
        println!();

        // Statistics
        println!("📈 Statistics:");
        println!("  Total Tests: {}", results.total_tests);
        println!("  {} Passed: {}", "✅".green(), results.passed);
        println!("  {} Failed: {}", "❌".red(), results.failed);
        println!("  {} Warnings: {}", "⚠️ ".yellow(), results.warnings);
        println!("  {} Skipped: {}", "⏭️ ".blue(), results.skipped);
        println!("  {} Errors: {}", "💥".red(), results.errors);
        println!();

        // Duration
        println!("⏱️  Duration: {:?}", results.duration);
        println!();

        // System info
        println!("🖥️  Target System:");
        println!("  Kernel: {}", results.system_info.kernel_version);
        println!("  Uptime: {}", results.system_info.uptime);

        // Display CPU information
        if !results.system_info.cpu_info.is_empty() {
            println!("  CPU: {}", results.system_info.cpu_info);
        }

        // Display memory usage
        if !results.system_info.memory_usage.is_empty() {
            println!("  Memory: {}", results.system_info.memory_usage);
        }

        // Display disk usage
        if !results.system_info.disk_usage.is_empty() {
            println!("  Disk: {}", results.system_info.disk_usage);
        }

        // Display power governor
        if !results.system_info.power_governor.is_empty() {
            println!("  Power Governor: {}", results.system_info.power_governor);
        }

        // Parse and display OS release information
        if !results.system_info.os_release.is_empty() {
            // Extract key information from /etc/os-release
            let mut os_name = String::new();
            let mut os_version = String::new();
            let mut os_id = String::new();
            let mut lmp_machine = String::new();
            let mut lmp_factory = String::new();
            let mut lmp_factory_tag = String::new();
            let mut image_version = String::new();
            let mut home_url = String::new();

            for line in results.system_info.os_release.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim_matches('"');
                    match key {
                        "PRETTY_NAME" => os_name = value.to_string(),
                        "VERSION" => os_version = value.to_string(),
                        "ID" => os_id = value.to_string(),
                        "LMP_MACHINE" => lmp_machine = value.to_string(),
                        "LMP_FACTORY" => lmp_factory = value.to_string(),
                        "LMP_FACTORY_TAG" => lmp_factory_tag = value.to_string(),
                        "IMAGE_VERSION" => image_version = value.to_string(),
                        "HOME_URL" => home_url = value.to_string(),
                        _ => {}
                    }
                }
            }

            // Display OS information
            if !os_name.is_empty() {
                println!("  OS: {}", os_name);
            } else if !os_id.is_empty() && !os_version.is_empty() {
                println!("  OS: {} {}", os_id, os_version);
            } else if !os_id.is_empty() {
                println!("  OS: {}", os_id);
            }

            // Display LMP-specific information if available
            if !lmp_machine.is_empty() {
                println!("  LMP Machine: {}", lmp_machine);
            }
            if !lmp_factory.is_empty() {
                println!("  LMP Factory: {}", lmp_factory);
            }
            if !lmp_factory_tag.is_empty() {
                println!("  Factory Tag: {}", lmp_factory_tag);
            }
            if !image_version.is_empty() {
                println!("  Image Version: {}", image_version);
            }
            if !home_url.is_empty() && home_url.contains("foundries.io") {
                println!("  Platform: Foundries.io Linux Micro Platform");
            }
        }

        // Display Foundries registration status
        if !results.system_info.foundries_registration.is_empty() {
            println!(
                "  Foundries Registration: {}",
                results.system_info.foundries_registration
            );
        }

        // Display WireGuard VPN status
        if !results.system_info.wireguard_status.is_empty() {
            println!("  WireGuard VPN: {}", results.system_info.wireguard_status);
        }

        println!();

        // Passed tests
        if results.passed > 0 {
            println!("{}", "✅ Passed Tests:".green().bold());
            for result in &results.results {
                if matches!(result.status, TestStatus::Passed) {
                    println!(
                        "  • {} - {}: {}",
                        result.test_id, result.test_name, result.message
                    );
                }
            }
            println!();
        }

        // Warnings
        if results.warnings > 0 {
            println!("{}", "⚠️  Warnings:".yellow().bold());
            for result in &results.results {
                if matches!(result.status, TestStatus::Warning) {
                    println!(
                        "  • {} - {}: {}",
                        result.test_id, result.test_name, result.message
                    );
                }
            }
            println!();
        }

        // Failed tests details
        if results.failed > 0 || results.errors > 0 {
            println!("{}", "❌ Failed Tests:".red().bold());
            for result in &results.results {
                if matches!(result.status, TestStatus::Failed | TestStatus::Error) {
                    println!(
                        "  • {} - {}: {}",
                        result.test_id, result.test_name, result.message
                    );
                }
            }
            println!();
        }

        Ok(())
    }

    async fn output_json(&self, results: &TestSuiteResults) -> Result<()> {
        let json = serde_json::to_string_pretty(results)?;
        println!("{}", json);
        Ok(())
    }

    async fn output_junit(&self, results: &TestSuiteResults) -> Result<()> {
        println!(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        println!(
            r#"<testsuites name="SecurityCompliance" tests="{}" failures="{}" errors="{}" time="{:.3}">"#,
            results.total_tests,
            results.failed,
            results.errors,
            results.duration.as_secs_f64()
        );

        println!(
            r#"  <testsuite name="{}" tests="{}" failures="{}" errors="{}" skipped="{}" time="{:.3}">"#,
            results.suite_name,
            results.total_tests,
            results.failed,
            results.errors,
            results.skipped,
            results.duration.as_secs_f64()
        );

        for result in &results.results {
            println!(
                r#"    <testcase name="{}" classname="{}" time="{:.3}">"#,
                result.test_name,
                result.category,
                result.duration.as_secs_f64()
            );

            match result.status {
                TestStatus::Failed => {
                    println!(
                        r#"      <failure message="{}">{}</failure>"#,
                        xml_escape(&result.message),
                        xml_escape(result.details.as_deref().unwrap_or(""))
                    );
                }
                TestStatus::Error => {
                    println!(
                        r#"      <error message="{}">{}</error>"#,
                        xml_escape(&result.message),
                        xml_escape(result.details.as_deref().unwrap_or(""))
                    );
                }
                TestStatus::Skipped => {
                    println!(
                        r#"      <skipped message="{}"/>"#,
                        xml_escape(&result.message)
                    );
                }
                _ => {}
            }

            println!(r#"    </testcase>"#);
        }

        println!(r#"  </testsuite>"#);
        println!(r#"</testsuites>"#);
        Ok(())
    }

    async fn output_markdown(&self, results: &TestSuiteResults) -> Result<()> {
        println!("## Results");
        println!();
        println!("| Metric | Value |");
        println!("| ------ | ----- |");
        println!(
            "| **Overall Status** | {} |",
            if results.overall_passed() {
                "✅ PASSED"
            } else {
                "❌ FAILED"
            }
        );
        println!("| **Success Rate** | {:.1}% |", results.success_rate());
        println!("| **Total Tests** | {} |", results.total_tests);
        println!("| **Passed** | ✅ {} |", results.passed);
        println!("| **Failed** | ❌ {} |", results.failed);
        println!("| **Warnings** | ⚠️ {} |", results.warnings);
        println!("| **Skipped** | ⏭️ {} |", results.skipped);
        println!("| **Errors** | 💥 {} |", results.errors);
        println!("| **Duration** | {:?} |", results.duration);
        println!();

        println!("## Test Details");
        println!();
        println!("| Test ID | Test Name | Status | Message |");
        println!("| ------- | --------- | ------ | ------- |");

        for result in &results.results {
            let status_icon = match result.status {
                TestStatus::Passed => "✅",
                TestStatus::Failed => "❌",
                TestStatus::Warning => "⚠️",
                TestStatus::Skipped => "⏭️",
                TestStatus::Error => "💥",
            };

            println!(
                "| {} | {} | {} | {} |",
                result.test_id, result.test_name, status_icon, result.message
            );
        }

        Ok(())
    }

    async fn output_cra_compliance(&self, results: &TestSuiteResults) -> Result<()> {
        let compliance_report = CraComplianceReporter::generate_report(results);
        let markdown_report = format_compliance_report_as_markdown(&compliance_report);
        println!("{}", markdown_report);
        Ok(())
    }

    async fn output_red_compliance(&self, results: &TestSuiteResults) -> Result<()> {
        let compliance_report = RedComplianceReporter::generate_report(results);
        let markdown_report = format_compliance_report_as_markdown(&compliance_report);
        println!("{}", markdown_report);
        Ok(())
    }

    async fn output_pdf_report(&self, results: &TestSuiteResults) -> Result<()> {
        // For PDF output, we need to determine which compliance framework to use
        // Default to CRA if not specified in config
        let compliance_report = CraComplianceReporter::generate_report(results);

        // Generate a default filename if none specified
        let default_filename = format!(
            "compliance-report-{}.pdf",
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        );

        let output_path = if let Some(file) = &self.config.file {
            file.clone()
        } else {
            default_filename
        };

        match generate_pdf_report(&compliance_report, &output_path) {
            Ok(()) => {
                println!("✅ PDF report generated successfully: {}", output_path);
            }
            Err(e) => {
                eprintln!("❌ Failed to generate PDF report: {}", e);
                return Err(crate::error::Error::Io(std::io::Error::other(format!(
                    "PDF generation failed: {}",
                    e
                ))));
            }
        }

        Ok(())
    }

    async fn write_to_file(&self, results: &TestSuiteResults, file_path: &str) -> Result<()> {
        let content = match self.config.format.as_str() {
            "json" => serde_json::to_string_pretty(results)?,
            "cra" => {
                let compliance_report = CraComplianceReporter::generate_report(results);
                format_compliance_report_as_markdown(&compliance_report)
            }
            "red" => {
                let compliance_report = RedComplianceReporter::generate_report(results);
                format_compliance_report_as_markdown(&compliance_report)
            }
            "pdf" => {
                // For PDF, we generate the file directly instead of returning content
                let compliance_report = CraComplianceReporter::generate_report(results);
                match generate_pdf_report(&compliance_report, file_path) {
                    Ok(()) => {
                        println!("PDF report written to: {}", file_path);
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(crate::error::Error::Io(std::io::Error::other(format!(
                            "PDF generation failed: {}",
                            e
                        ))));
                    }
                }
            }
            "junit" => {
                // Generate JUnit XML content
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="SecurityCompliance" tests="{}" failures="{}" errors="{}" time="{:.3}">
  <testsuite name="{}" tests="{}" failures="{}" errors="{}" skipped="{}" time="{:.3}">
{}
  </testsuite>
</testsuites>"#,
                    results.total_tests,
                    results.failed,
                    results.errors,
                    results.duration.as_secs_f64(),
                    results.suite_name,
                    results.total_tests,
                    results.failed,
                    results.errors,
                    results.skipped,
                    results.duration.as_secs_f64(),
                    results
                        .results
                        .iter()
                        .map(|r| format!(
                            r#"    <testcase name="{}" classname="{}" time="{:.3}"/>"#,
                            r.test_name,
                            r.category,
                            r.duration.as_secs_f64()
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            }
            _ => format!("Security Compliance Test Results\n{:#?}", results),
        };

        fs::write(file_path, content)?;
        println!("Results written to: {}", file_path);
        Ok(())
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
