# Compliance Reporting

The Security Compliance CLI now supports specialized compliance reporting formats for regulatory frameworks:

## Available Compliance Formats

### EU Cyber Resilience Act (CRA) - `--format cra`

Generates compliance reports aligned with the EU Cyber Resilience Act requirements:

```bash
# Generate CRA compliance report to console
./security-compliance-cli test --format cra

# Generate CRA compliance report to file
./security-compliance-cli test --format cra --output cra-compliance-report.md

# CRA compliance for specific machine type
./security-compliance-cli test --format cra --machine imx93-jaguar-eink --output imx93-cra-report.md
```

### UK CE RED Directive - `--format red`

Generates compliance reports for UK CE Radio Equipment Directive:

```bash
# Generate RED compliance report to console
./security-compliance-cli test --format red

# Generate RED compliance report to file
./security-compliance-cli test --format red --output red-compliance-report.md

# RED compliance for wireless devices
./security-compliance-cli test --format red --machine imx8mm-jaguar-sentai --output sentai-red-report.md
```

### PDF Reports - `--format pdf`

Generate professional PDF compliance reports suitable for formal documentation:

```bash
# Generate PDF compliance report (defaults to CRA framework)
./security-compliance-cli test --format pdf --output compliance-report.pdf

# Generate PDF report with automatic timestamped filename
./security-compliance-cli test --format pdf

# Generate PDF for specific machine with custom filename
./security-compliance-cli test --format pdf --machine imx93-jaguar-eink --output imx93-cra-compliance.pdf
```

**PDF Features:**
- Professional formatting with proper typography
- Multi-page support with automatic page breaks
- Structured sections with clear headings
- Tabular test results with status indicators
- Certification readiness assessment
- Ready for submission to certification bodies

## Requirement Mappings

### **CRA Requirements Mapped:**
- **CRA-ART11-001**: Data Protection by Design and Default
- **CRA-ART11-002**: Vulnerability Management Process  
- **CRA-ART11-003**: Security Audit Logging
- **CRA-ART11-004**: Secure Boot Implementation
- **CRA-ART11-005**: Hardware Root of Trust

### **RED Requirements Mapped:**
- **RED-ER3.3-001**: Cybersecurity Features
- **RED-ER3.3-002**: Network Security Controls
- **RED-ER3.3-003**: Wireless Communication Security
- **RED-ER3.3-004**: Default Credentials Management

## Report Structure

Both compliance reports include:

### 📋 **Product Information**
- Product name, version, manufacturer
- Model and description details

### 📊 **Compliance Summary**
- Overall compliance status
- Compliance percentage
- Breakdown of passed/failed/warning requirements

### 📝 **Detailed Test Results**
- Requirement ID mapping
- Test status with visual indicators
- Risk level assessment
- Evidence and remediation guidance

### ✅ **Certification Readiness**
- Ready for certification status
- Blocking issues (if any)
- Warnings and recommendations
- Next steps for compliance

## Configuration Examples

### CRA Compliance Configuration

```toml
[target]
host = "192.168.1.100"
user = "root"
ssh_key_path = "/path/to/key"

[output]
format = "cra"
file = "cra-compliance-report.md"
verbose = 2

[tests]
suite = "compliance"
mode = "production"

[machine]
machine_type = "imx93-jaguar-eink"
auto_detect = false
```

### RED Compliance Configuration

```toml
[target]
host = "192.168.1.101"
user = "root"
ssh_key_path = "/path/to/key"

[output]
format = "red"
file = "red-compliance-report.md"
verbose = 2

[tests]
suite = "all"
mode = "production"

[machine]
machine_type = "imx8mm-jaguar-sentai"
auto_detect = false
```

### PDF Report Configuration

```toml
[target]
host = "192.168.1.100"
user = "root"
ssh_key_path = "/path/to/key"

[output]
format = "pdf"
file = "compliance-report.pdf"
verbose = 1

[tests]
suite = "compliance"
mode = "production"

[machine]
machine_type = "imx93-jaguar-eink"
auto_detect = false
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
- name: Run CRA Compliance Check
  run: |
    ./security-compliance-cli test \
      --format cra \
      --output cra-compliance-report.md \
      --host ${{ secrets.TARGET_HOST }} \
      --user ${{ secrets.TARGET_USER }} \
      --identity-file ${{ secrets.SSH_KEY_PATH }}

- name: Generate PDF Compliance Report
  run: |
    ./security-compliance-cli test \
      --format pdf \
      --output compliance-report.pdf \
      --host ${{ secrets.TARGET_HOST }} \
      --user ${{ secrets.TARGET_USER }} \
      --identity-file ${{ secrets.SSH_KEY_PATH }}

- name: Upload Compliance Reports
  uses: actions/upload-artifact@v4
  with:
    name: compliance-reports
    path: |
      cra-compliance-report.md
      compliance-report.pdf
```

### GitLab CI Example

```yaml
cra_compliance:
  stage: compliance
  script:
    - ./security-compliance-cli test --format cra --output cra-report.md
    - ./security-compliance-cli test --format pdf --output compliance-report.pdf
  artifacts:
    reports:
      compliance: cra-report.md
    paths:
      - compliance-report.pdf
    expire_in: 30 days
```

## Certification Process

### For CRA Compliance:
1. Run compliance tests: `--format cra`
2. Address all failing requirements
3. Review warnings and recommendations
4. Generate final compliance report
5. Engage with notified body for assessment

### For RED Compliance:
1. Run compliance tests: `--format red`
2. Ensure all cybersecurity requirements pass
3. Complete EMC and radio testing separately
4. Generate technical documentation
5. Apply CE marking and submit declaration

## Customization

The compliance mappings can be extended by modifying:
- `src/compliance.rs` - Add new requirement mappings
- Test implementations - Ensure tests cover regulatory requirements
- Machine detection - Add hardware-specific compliance rules

For questions or support with compliance reporting, contact: info@dynamicdevices.co.uk
