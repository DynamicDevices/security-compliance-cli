/*
 * Security Compliance CLI - Compliance Reporting
 * Copyright (C) 2025 Dynamic Devices Ltd
 * Licensed under GPLv3 - see LICENSE file for details
 */

use crate::tests::{TestStatus, TestSuiteResults};
use chrono::{DateTime, Utc};
use printpdf::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_type: String,
    pub generated_at: DateTime<Utc>,
    pub product_info: ProductInfo,
    pub compliance_summary: ComplianceSummary,
    pub test_results: Vec<ComplianceTestResult>,
    pub recommendations: Vec<String>,
    pub certification_status: CertificationStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductInfo {
    pub name: String,
    pub version: String,
    pub manufacturer: String,
    pub model: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSummary {
    pub total_requirements: usize,
    pub passed_requirements: usize,
    pub failed_requirements: usize,
    pub warning_requirements: usize,
    pub compliance_percentage: f64,
    pub overall_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceTestResult {
    pub requirement_id: String,
    pub requirement_title: String,
    pub requirement_description: String,
    pub test_id: String,
    pub status: String,
    pub evidence: String,
    pub remediation: Option<String>,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificationStatus {
    pub ready_for_certification: bool,
    pub blocking_issues: Vec<String>,
    pub warnings: Vec<String>,
    pub next_steps: Vec<String>,
}

pub struct CraComplianceReporter;

impl CraComplianceReporter {
    pub fn generate_report(results: &TestSuiteResults) -> ComplianceReport {
        let cra_mapping = Self::get_cra_test_mapping();
        let mut compliance_results = Vec::new();
        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;

        // Map test results to CRA requirements
        for result in &results.results {
            if let Some(cra_req) = cra_mapping.get(&result.test_id) {
                let status = match result.status {
                    TestStatus::Passed => {
                        passed += 1;
                        "COMPLIANT"
                    }
                    TestStatus::Failed => {
                        failed += 1;
                        "NON_COMPLIANT"
                    }
                    TestStatus::Warning => {
                        warnings += 1;
                        "PARTIAL_COMPLIANCE"
                    }
                    TestStatus::Skipped => "NOT_TESTED",
                    TestStatus::Error => "ERROR",
                };

                compliance_results.push(ComplianceTestResult {
                    requirement_id: cra_req.requirement_id.clone(),
                    requirement_title: cra_req.title.clone(),
                    requirement_description: cra_req.description.clone(),
                    test_id: result.test_id.clone(),
                    status: status.to_string(),
                    evidence: result.details.clone().unwrap_or_default(),
                    remediation: cra_req.remediation.clone(),
                    risk_level: cra_req.risk_level.clone(),
                });
            }
        }

        let total = compliance_results.len();
        let compliance_percentage = if total > 0 {
            (passed as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let overall_status = if failed == 0 && warnings == 0 {
            "FULLY_COMPLIANT"
        } else if failed == 0 {
            "COMPLIANT_WITH_WARNINGS"
        } else {
            "NON_COMPLIANT"
        };

        ComplianceReport {
            report_type: "EU_CYBER_RESILIENCE_ACT".to_string(),
            generated_at: Utc::now(),
            product_info: ProductInfo {
                name: "Embedded Linux Device".to_string(),
                version: "1.0.0".to_string(),
                manufacturer: "Dynamic Devices Ltd".to_string(),
                model: "Security Compliance Device".to_string(),
                description: "Embedded Linux device with security compliance testing".to_string(),
            },
            compliance_summary: ComplianceSummary {
                total_requirements: total,
                passed_requirements: passed,
                failed_requirements: failed,
                warning_requirements: warnings,
                compliance_percentage,
                overall_status: overall_status.to_string(),
            },
            test_results: compliance_results,
            recommendations: Self::generate_recommendations(failed, warnings),
            certification_status: Self::assess_certification_readiness(failed, warnings),
        }
    }

    fn get_cra_test_mapping() -> HashMap<String, CraRequirement> {
        let mut mapping = HashMap::new();

        // Article 11 - Data Protection Requirements
        mapping.insert(
            "compliance_001".to_string(),
            CraRequirement {
                requirement_id: "CRA-ART11-001".to_string(),
                title: "Data Protection by Design and Default".to_string(),
                description: "Products must implement data protection by design and by default, including encryption at rest and in transit".to_string(),
                remediation: Some("Implement full disk encryption and secure communication protocols".to_string()),
                risk_level: "HIGH".to_string(),
            },
        );

        // Article 11 - Vulnerability Management
        mapping.insert(
            "compliance_002".to_string(),
            CraRequirement {
                requirement_id: "CRA-ART11-002".to_string(),
                title: "Vulnerability Management Process".to_string(),
                description: "Manufacturers must establish processes for handling vulnerabilities and security updates".to_string(),
                remediation: Some("Implement automated security update mechanisms and vulnerability disclosure process".to_string()),
                risk_level: "HIGH".to_string(),
            },
        );

        // Security Audit Logging
        mapping.insert(
            "compliance_005".to_string(),
            CraRequirement {
                requirement_id: "CRA-ART11-003".to_string(),
                title: "Security Audit Logging".to_string(),
                description: "Products must maintain comprehensive security audit logs for compliance and forensic analysis".to_string(),
                remediation: Some("Enable comprehensive audit logging and secure log storage".to_string()),
                risk_level: "MEDIUM".to_string(),
            },
        );

        // Boot Security
        mapping.insert(
            "boot_001".to_string(),
            CraRequirement {
                requirement_id: "CRA-ART11-004".to_string(),
                title: "Secure Boot Implementation".to_string(),
                description: "Products must implement secure boot to ensure only authenticated firmware executes".to_string(),
                remediation: Some("Enable and configure secure boot with proper key management".to_string()),
                risk_level: "HIGH".to_string(),
            },
        );

        // Hardware Security
        mapping.insert(
            "hardware_001".to_string(),
            CraRequirement {
                requirement_id: "CRA-ART11-005".to_string(),
                title: "Hardware Root of Trust".to_string(),
                description:
                    "Products must utilize hardware-based security features for establishing trust"
                        .to_string(),
                remediation: Some(
                    "Utilize hardware security modules and secure enclaves".to_string(),
                ),
                risk_level: "HIGH".to_string(),
            },
        );

        mapping
    }

    fn generate_recommendations(failed: usize, warnings: usize) -> Vec<String> {
        let mut recommendations = Vec::new();

        if failed > 0 {
            recommendations
                .push("Address all failing compliance tests before certification".to_string());
            recommendations.push(
                "Implement missing security controls identified in test failures".to_string(),
            );
        }

        if warnings > 0 {
            recommendations.push(
                "Review and address warning conditions to improve security posture".to_string(),
            );
        }

        recommendations
            .push("Conduct regular security assessments throughout product lifecycle".to_string());
        recommendations.push(
            "Establish incident response procedures for security vulnerabilities".to_string(),
        );
        recommendations
            .push("Implement continuous monitoring and logging for security events".to_string());

        recommendations
    }

    fn assess_certification_readiness(failed: usize, warnings: usize) -> CertificationStatus {
        let ready = failed == 0;
        let mut blocking_issues = Vec::new();
        let mut warnings_list = Vec::new();
        let mut next_steps = Vec::new();

        if failed > 0 {
            blocking_issues.push(format!(
                "{} critical compliance requirements failing",
                failed
            ));
            next_steps
                .push("Resolve all failing tests before proceeding with certification".to_string());
        }

        if warnings > 0 {
            warnings_list.push(format!(
                "{} requirements have warnings that should be addressed",
                warnings
            ));
            next_steps.push("Review and address warning conditions".to_string());
        }

        if ready {
            next_steps.push("Product appears ready for CRA compliance certification".to_string());
            next_steps.push("Engage with notified body for formal assessment".to_string());
        }

        CertificationStatus {
            ready_for_certification: ready,
            blocking_issues,
            warnings: warnings_list,
            next_steps,
        }
    }
}

pub struct RedComplianceReporter;

impl RedComplianceReporter {
    pub fn generate_report(results: &TestSuiteResults) -> ComplianceReport {
        let red_mapping = Self::get_red_test_mapping();
        let mut compliance_results = Vec::new();
        let mut passed = 0;
        let mut failed = 0;
        let mut warnings = 0;

        // Map test results to RED requirements
        for result in &results.results {
            if let Some(red_req) = red_mapping.get(&result.test_id) {
                let status = match result.status {
                    TestStatus::Passed => {
                        passed += 1;
                        "COMPLIANT"
                    }
                    TestStatus::Failed => {
                        failed += 1;
                        "NON_COMPLIANT"
                    }
                    TestStatus::Warning => {
                        warnings += 1;
                        "PARTIAL_COMPLIANCE"
                    }
                    TestStatus::Skipped => "NOT_TESTED",
                    TestStatus::Error => "ERROR",
                };

                compliance_results.push(ComplianceTestResult {
                    requirement_id: red_req.requirement_id.clone(),
                    requirement_title: red_req.title.clone(),
                    requirement_description: red_req.description.clone(),
                    test_id: result.test_id.clone(),
                    status: status.to_string(),
                    evidence: result.details.clone().unwrap_or_default(),
                    remediation: red_req.remediation.clone(),
                    risk_level: red_req.risk_level.clone(),
                });
            }
        }

        let total = compliance_results.len();
        let compliance_percentage = if total > 0 {
            (passed as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let overall_status = if failed == 0 && warnings == 0 {
            "FULLY_COMPLIANT"
        } else if failed == 0 {
            "COMPLIANT_WITH_WARNINGS"
        } else {
            "NON_COMPLIANT"
        };

        ComplianceReport {
            report_type: "UK_CE_RED_DIRECTIVE".to_string(),
            generated_at: Utc::now(),
            product_info: ProductInfo {
                name: "Radio Equipment Device".to_string(),
                version: "1.0.0".to_string(),
                manufacturer: "Dynamic Devices Ltd".to_string(),
                model: "Radio Compliance Device".to_string(),
                description: "Radio equipment with RED compliance features".to_string(),
            },
            compliance_summary: ComplianceSummary {
                total_requirements: total,
                passed_requirements: passed,
                failed_requirements: failed,
                warning_requirements: warnings,
                compliance_percentage,
                overall_status: overall_status.to_string(),
            },
            test_results: compliance_results,
            recommendations: Self::generate_recommendations(failed, warnings),
            certification_status: Self::assess_certification_readiness(failed, warnings),
        }
    }

    fn get_red_test_mapping() -> HashMap<String, RedRequirement> {
        let mut mapping = HashMap::new();

        // RED Essential Requirement 3.3 - Cybersecurity
        mapping.insert(
            "compliance_003".to_string(),
            RedRequirement {
                requirement_id: "RED-ER3.3-001".to_string(),
                title: "Cybersecurity Features".to_string(),
                description: "Radio equipment must incorporate appropriate cybersecurity features to prevent unauthorized access".to_string(),
                remediation: Some("Implement access controls, encryption, and secure authentication".to_string()),
                risk_level: "HIGH".to_string(),
            },
        );

        // Network Security
        mapping.insert(
            "network_001".to_string(),
            RedRequirement {
                requirement_id: "RED-ER3.3-002".to_string(),
                title: "Network Security Controls".to_string(),
                description: "Radio equipment must implement appropriate network security controls"
                    .to_string(),
                remediation: Some(
                    "Configure firewalls, secure protocols, and network access controls"
                        .to_string(),
                ),
                risk_level: "HIGH".to_string(),
            },
        );

        // WiFi Security
        mapping.insert(
            "network_003".to_string(),
            RedRequirement {
                requirement_id: "RED-ER3.3-003".to_string(),
                title: "Wireless Communication Security".to_string(),
                description: "Wireless communications must use appropriate security protocols"
                    .to_string(),
                remediation: Some(
                    "Implement WPA3/WPA2 encryption and secure wireless protocols".to_string(),
                ),
                risk_level: "HIGH".to_string(),
            },
        );

        // Default Credentials
        mapping.insert(
            "production_003".to_string(),
            RedRequirement {
                requirement_id: "RED-ER3.3-004".to_string(),
                title: "Default Credentials Management".to_string(),
                description: "Radio equipment must not use default or easily guessable credentials"
                    .to_string(),
                remediation: Some(
                    "Change all default passwords and implement strong authentication".to_string(),
                ),
                risk_level: "HIGH".to_string(),
            },
        );

        mapping
    }

    fn generate_recommendations(failed: usize, warnings: usize) -> Vec<String> {
        let mut recommendations = Vec::new();

        if failed > 0 {
            recommendations.push(
                "Address all failing RED compliance requirements before CE marking".to_string(),
            );
            recommendations
                .push("Implement required cybersecurity features for radio equipment".to_string());
        }

        if warnings > 0 {
            recommendations
                .push("Review warning conditions to ensure full RED compliance".to_string());
        }

        recommendations.push("Conduct electromagnetic compatibility (EMC) testing".to_string());
        recommendations.push("Prepare technical documentation for RED compliance".to_string());
        recommendations
            .push("Engage with notified body for conformity assessment if required".to_string());

        recommendations
    }

    fn assess_certification_readiness(failed: usize, warnings: usize) -> CertificationStatus {
        let ready = failed == 0;
        let mut blocking_issues = Vec::new();
        let mut warnings_list = Vec::new();
        let mut next_steps = Vec::new();

        if failed > 0 {
            blocking_issues.push(format!("{} critical RED requirements failing", failed));
            next_steps.push("Resolve all failing tests before CE marking".to_string());
        }

        if warnings > 0 {
            warnings_list.push(format!("{} requirements have warnings", warnings));
            next_steps.push("Address warning conditions for full compliance".to_string());
        }

        if ready {
            next_steps.push("Product appears ready for RED compliance and CE marking".to_string());
            next_steps
                .push("Complete technical documentation and conformity assessment".to_string());
        }

        CertificationStatus {
            ready_for_certification: ready,
            blocking_issues,
            warnings: warnings_list,
            next_steps,
        }
    }
}

#[derive(Debug, Clone)]
struct CraRequirement {
    requirement_id: String,
    title: String,
    description: String,
    remediation: Option<String>,
    risk_level: String,
}

#[derive(Debug, Clone)]
struct RedRequirement {
    requirement_id: String,
    title: String,
    description: String,
    remediation: Option<String>,
    risk_level: String,
}

pub fn format_compliance_report_as_markdown(report: &ComplianceReport) -> String {
    let mut output = String::new();

    output.push_str(&format!("# {} Compliance Report\n\n", report.report_type));
    output.push_str(&format!(
        "**Generated:** {}\n\n",
        report.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Product Information
    output.push_str("## Product Information\n\n");
    output.push_str(&format!("- **Name:** {}\n", report.product_info.name));
    output.push_str(&format!("- **Version:** {}\n", report.product_info.version));
    output.push_str(&format!(
        "- **Manufacturer:** {}\n",
        report.product_info.manufacturer
    ));
    output.push_str(&format!("- **Model:** {}\n", report.product_info.model));
    output.push_str(&format!(
        "- **Description:** {}\n\n",
        report.product_info.description
    ));

    // Compliance Summary
    output.push_str("## Compliance Summary\n\n");
    output.push_str(&format!(
        "- **Overall Status:** {}\n",
        report.compliance_summary.overall_status
    ));
    output.push_str(&format!(
        "- **Compliance Percentage:** {:.1}%\n",
        report.compliance_summary.compliance_percentage
    ));
    output.push_str(&format!(
        "- **Total Requirements:** {}\n",
        report.compliance_summary.total_requirements
    ));
    output.push_str(&format!(
        "- **Passed:** {}\n",
        report.compliance_summary.passed_requirements
    ));
    output.push_str(&format!(
        "- **Failed:** {}\n",
        report.compliance_summary.failed_requirements
    ));
    output.push_str(&format!(
        "- **Warnings:** {}\n\n",
        report.compliance_summary.warning_requirements
    ));

    // Test Results
    output.push_str("## Detailed Test Results\n\n");
    output.push_str("| Requirement ID | Title | Status | Risk Level |\n");
    output.push_str("|---|---|---|---|\n");

    for result in &report.test_results {
        let status_emoji = match result.status.as_str() {
            "COMPLIANT" => "✅",
            "NON_COMPLIANT" => "❌",
            "PARTIAL_COMPLIANCE" => "⚠️",
            _ => "❓",
        };
        output.push_str(&format!(
            "| {} | {} | {} {} | {} |\n",
            result.requirement_id,
            result.requirement_title,
            status_emoji,
            result.status,
            result.risk_level
        ));
    }

    // Certification Status
    output.push_str("\n## Certification Readiness\n\n");
    let ready_emoji = if report.certification_status.ready_for_certification {
        "✅"
    } else {
        "❌"
    };
    output.push_str(&format!(
        "**Ready for Certification:** {} {}\n\n",
        ready_emoji, report.certification_status.ready_for_certification
    ));

    if !report.certification_status.blocking_issues.is_empty() {
        output.push_str("### Blocking Issues\n\n");
        for issue in &report.certification_status.blocking_issues {
            output.push_str(&format!("- ❌ {}\n", issue));
        }
        output.push('\n');
    }

    if !report.certification_status.warnings.is_empty() {
        output.push_str("### Warnings\n\n");
        for warning in &report.certification_status.warnings {
            output.push_str(&format!("- ⚠️ {}\n", warning));
        }
        output.push('\n');
    }

    // Next Steps
    output.push_str("### Next Steps\n\n");
    for step in &report.certification_status.next_steps {
        output.push_str(&format!("1. {}\n", step));
    }

    // Recommendations
    output.push_str("\n## Recommendations\n\n");
    for recommendation in &report.recommendations {
        output.push_str(&format!("- {}\n", recommendation));
    }

    output
}

pub fn generate_pdf_report(
    report: &ComplianceReport,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a new PDF document
    let (doc, page1, layer1) =
        PdfDocument::new("Compliance Report", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page1).get_layer(layer1);

    // Load fonts
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    let font_regular = doc.add_builtin_font(BuiltinFont::Helvetica)?;

    let mut y_position = Mm(270.0); // Start near top of page
    let left_margin = Mm(20.0);
    let right_margin = Mm(190.0);

    // Title
    current_layer.use_text(
        format!("{} Compliance Report", report.report_type),
        18.0,
        left_margin,
        y_position,
        &font_bold,
    );
    y_position -= Mm(15.0);

    // Generated date
    current_layer.use_text(
        format!(
            "Generated: {}",
            report.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
        ),
        12.0,
        left_margin,
        y_position,
        &font_regular,
    );
    y_position -= Mm(20.0);

    // Product Information Section
    current_layer.use_text(
        "Product Information",
        14.0,
        left_margin,
        y_position,
        &font_bold,
    );
    y_position -= Mm(10.0);

    let product_info = vec![
        format!("Name: {}", report.product_info.name),
        format!("Version: {}", report.product_info.version),
        format!("Manufacturer: {}", report.product_info.manufacturer),
        format!("Model: {}", report.product_info.model),
        format!("Description: {}", report.product_info.description),
    ];

    for info in product_info {
        current_layer.use_text(info, 10.0, left_margin + Mm(5.0), y_position, &font_regular);
        y_position -= Mm(6.0);
    }
    y_position -= Mm(10.0);

    // Compliance Summary Section
    current_layer.use_text(
        "Compliance Summary",
        14.0,
        left_margin,
        y_position,
        &font_bold,
    );
    y_position -= Mm(10.0);

    let summary_info = vec![
        format!(
            "Overall Status: {}",
            report.compliance_summary.overall_status
        ),
        format!(
            "Compliance Percentage: {:.1}%",
            report.compliance_summary.compliance_percentage
        ),
        format!(
            "Total Requirements: {}",
            report.compliance_summary.total_requirements
        ),
        format!("Passed: {}", report.compliance_summary.passed_requirements),
        format!("Failed: {}", report.compliance_summary.failed_requirements),
        format!(
            "Warnings: {}",
            report.compliance_summary.warning_requirements
        ),
    ];

    for info in summary_info {
        current_layer.use_text(info, 10.0, left_margin + Mm(5.0), y_position, &font_regular);
        y_position -= Mm(6.0);
    }
    y_position -= Mm(10.0);

    // Test Results Section
    current_layer.use_text("Test Results", 14.0, left_margin, y_position, &font_bold);
    y_position -= Mm(10.0);

    // Table headers
    current_layer.use_text("Requirement ID", 10.0, left_margin, y_position, &font_bold);
    current_layer.use_text(
        "Title",
        10.0,
        left_margin + Mm(40.0),
        y_position,
        &font_bold,
    );
    current_layer.use_text(
        "Status",
        10.0,
        left_margin + Mm(100.0),
        y_position,
        &font_bold,
    );
    current_layer.use_text(
        "Risk",
        10.0,
        left_margin + Mm(130.0),
        y_position,
        &font_bold,
    );
    y_position -= Mm(8.0);

    // Draw a line under headers
    let line_points = vec![
        (Point::new(left_margin, y_position + Mm(2.0)), false),
        (Point::new(right_margin, y_position + Mm(2.0)), false),
    ];
    let line = Line {
        points: line_points,
        is_closed: false,
    };
    current_layer.add_line(line);
    y_position -= Mm(5.0);

    // Test results rows
    for result in &report.test_results {
        // Check if we need a new page
        if y_position < Mm(30.0) {
            let (_page, _layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
            y_position = Mm(270.0);
        }

        // Truncate long text to fit in columns
        let req_id = if result.requirement_id.len() > 15 {
            format!("{}...", &result.requirement_id[..12])
        } else {
            result.requirement_id.clone()
        };

        let title = if result.requirement_title.len() > 25 {
            format!("{}...", &result.requirement_title[..22])
        } else {
            result.requirement_title.clone()
        };

        current_layer.use_text(req_id, 9.0, left_margin, y_position, &font_regular);
        current_layer.use_text(
            title,
            9.0,
            left_margin + Mm(40.0),
            y_position,
            &font_regular,
        );
        current_layer.use_text(
            result.status.clone(),
            9.0,
            left_margin + Mm(100.0),
            y_position,
            &font_regular,
        );
        current_layer.use_text(
            result.risk_level.clone(),
            9.0,
            left_margin + Mm(130.0),
            y_position,
            &font_regular,
        );
        y_position -= Mm(6.0);
    }

    y_position -= Mm(10.0);

    // Certification Status Section
    if y_position < Mm(50.0) {
        let (_page, _layer) = doc.add_page(Mm(210.0), Mm(297.0), "Layer 1");
        y_position = Mm(270.0);
    }

    current_layer.use_text(
        "Certification Readiness",
        14.0,
        left_margin,
        y_position,
        &font_bold,
    );
    y_position -= Mm(10.0);

    let ready_status = if report.certification_status.ready_for_certification {
        "✓ Ready for Certification"
    } else {
        "✗ Not Ready for Certification"
    };
    current_layer.use_text(
        ready_status,
        12.0,
        left_margin + Mm(5.0),
        y_position,
        &font_regular,
    );
    y_position -= Mm(15.0);

    // Blocking Issues
    if !report.certification_status.blocking_issues.is_empty() {
        current_layer.use_text(
            "Blocking Issues:",
            12.0,
            left_margin,
            y_position,
            &font_bold,
        );
        y_position -= Mm(8.0);
        for issue in &report.certification_status.blocking_issues {
            current_layer.use_text(
                format!("• {}", issue),
                10.0,
                left_margin + Mm(5.0),
                y_position,
                &font_regular,
            );
            y_position -= Mm(6.0);
        }
        y_position -= Mm(5.0);
    }

    // Next Steps
    current_layer.use_text("Next Steps:", 12.0, left_margin, y_position, &font_bold);
    y_position -= Mm(8.0);
    for step in &report.certification_status.next_steps {
        current_layer.use_text(
            format!("1. {}", step),
            10.0,
            left_margin + Mm(5.0),
            y_position,
            &font_regular,
        );
        y_position -= Mm(6.0);
    }

    // Save the PDF
    doc.save(&mut BufWriter::new(File::create(output_path)?))?;

    Ok(())
}
