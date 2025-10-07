# Security Compliance Fixes for Foundries.io LMP

## 📊 Current Security Status (Updated October 7, 2025)

Based on latest test results from the security compliance CLI v0.3.1, here's the current security posture and recommended improvements for the imx93-jaguar-eink board running Foundries.io LMP v4.0.20-2156-94.

### 🎯 Test Results Summary
- **Total Tests**: 65 comprehensive security tests
- **Current Success Rate**: ~65-70% (varies by test suite)
- **Critical Issues**: Hardware RNG, CAAM crypto, SSH security
- **Platform**: imx93-jaguar-eink with EdgeLock Enclave (ELE)

## 🔥 Priority 1: Critical Security Issues

### 1. SSH Security Configuration (CRITICAL)
**Test**: `runtime_004` - SSH Security Configuration  
**Status**: ❌ FAILED - "SSH critical security issues: Root login permitted"  
**Risk Level**: CRITICAL

#### Problem
- Root login is permitted via SSH (major security vulnerability)
- This allows direct root access over the network
- Violates security best practices for production systems

#### Solution
Add to your `meta-subscriber-overrides` layer:

**File**: `meta-subscriber-overrides/recipes-connectivity/openssh/openssh_%.bbappend`
```bitbake
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"
SRC_URI:append = " file://sshd_config_security"

do_install:append() {
    # Apply security hardening to SSH configuration
    cat ${WORKDIR}/sshd_config_security >> ${D}${sysconfdir}/ssh/sshd_config
}
```

**File**: `meta-subscriber-overrides/recipes-connectivity/openssh/files/sshd_config_security`
```
# Security hardening for production systems
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxSessions 4
Protocol 2
```

#### Expected Result
- SSH security test changes from FAILED to PASSED
- Root login disabled, requiring user account access
- Enhanced SSH security configuration

### 2. Hardware RNG Entropy (HIGH PRIORITY)
**Test**: `hardware_005` - Hardware RNG  
**Status**: ❌ FAILED - "Insufficient entropy (256 bits)"  
**Risk Level**: HIGH

#### Problem
- Current entropy: 256 bits (insufficient for production)
- ELE-TRNG hardware working but not feeding kernel entropy pool
- Missing `rngd` daemon to bridge hardware RNG to kernel

#### Solution
```bitbake
# Fix hardware RNG entropy in lmp-factory-image.bbappend
IMAGE_INSTALL:append:imx93-jaguar-eink = " rng-tools"

# Enable rng-tools service
SYSTEMD_AUTO_ENABLE:pn-rng-tools = "enable"
```

#### Expected Result
- Entropy increases from 256 to 1000+ bits
- Hardware RNG test changes from FAILED to PASSED
- Improved cryptographic security

### 3. i.MX93 CAAM Crypto Acceleration (HIGH PRIORITY)
**Test**: `hardware_004` - Crypto Hardware Acceleration  
**Status**: ❌ FAILED - "Hardware crypto acceleration not detected"  
**Risk Level**: HIGH

#### Problem
- CAAM (Cryptographic Acceleration and Assurance Module) not enabled
- Crypto operations running in software only
- Missing performance and security benefits

#### Solution
See detailed instructions in [docs/ENABLE_CAAM_CRYPTO.md](docs/ENABLE_CAAM_CRYPTO.md)

Quick fix - add to kernel config:
```bitbake
# In meta-subscriber-overrides/recipes-kernel/linux/linux-lmp_%.bbappend
SRC_URI:append:imx93-jaguar-eink = " file://imx93-caam.cfg"
```

With config fragment:
```
CONFIG_CRYPTO_DEV_FSL_CAAM=y
CONFIG_CRYPTO_DEV_FSL_CAAM_JR=y
CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_AHASH_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_RNG_API=y
```

---

## 📋 Priority 2: Compliance and Audit Issues

### 4. Audit Logging (COMPLIANCE REQUIRED)
**Test**: `compliance_005` - Security Audit Logging  
**Status**: ❌ FAILED - "Insufficient audit logging"  
**Risk Level**: MEDIUM (High for compliance)

#### Problem
- No audit daemon running
- Cannot track security events
- EU CRA and UK CE RED compliance requirements not met

#### Solution
See detailed instructions in [docs/ENABLE_AUDIT_LOGGING.md](docs/ENABLE_AUDIT_LOGGING.md)

Quick fix:
```bitbake
IMAGE_INSTALL:append:imx93-jaguar-eink = " audit logrotate"
SYSTEMD_AUTO_ENABLE:pn-audit = "enable"
```

#### Expected Result
- Audit logging test changes from FAILED to PASSED
- Security events tracked and logged
- Compliance requirements met

### 5. Certificate Monitoring (MEDIUM PRIORITY)
**Test**: `certificate_003` - Certificate Expiration Monitoring  
**Status**: ❌ FAILED - "No certificate expiration monitoring"  
**Risk Level**: MEDIUM

#### Problem
- No certificate expiration monitoring
- Risk of expired certificates causing service failures
- No automated certificate lifecycle management

#### Solution
```bitbake
IMAGE_INSTALL:append:imx93-jaguar-eink = " certwatch"
```

Or create custom monitoring script:
```bash
#!/bin/bash
# Certificate monitoring script
find /etc/ssl/certs -name "*.pem" -exec openssl x509 -in {} -noout -enddate \; 2>/dev/null
```

---

## 🟡 Priority 3: Non-Critical Issues

### 6. Firewall Configuration (Pre-production Expected)
**Test**: `runtime_002` - Firewall Configuration  
**Status**: ⚠️ WARNING - "Firewall not configured"  
**Risk Level**: LOW (Expected in pre-production)

#### Note
This is expected behavior for pre-production testing. The firewall test should be enhanced to be mode-aware:
- **Pre-production mode**: Should show WARNING (current behavior)
- **Production mode**: Should require firewall configuration

### 7. Container Security (Optional)
**Tests**: `container_001`, `container_004`, `container_005`, `container_007`  
**Status**: ❌ FAILED - "Container runtime not available"  
**Risk Level**: LOW (If not using containers)

#### Note
These failures can be ignored if you're not using containers in your deployment.

If not using containers, configure test suite to skip:
```toml
[tests]
suite = "boot,runtime,hardware,network,compliance,certificate"  # Skip container tests
```

---

## 📊 Expected Security Improvement

### After Implementing Priority 1 & 2 Fixes:
- **Success Rate**: Should improve from ~65% to ~85%+
- **Critical Issues**: Reduced from 3 to 0
- **Compliance Status**: Significantly enhanced
- **Security Posture**: Production-ready level

### Test Results Projection:
- **SSH Security**: FAILED → PASSED
- **Hardware RNG**: FAILED → PASSED  
- **CAAM Crypto**: FAILED → PASSED
- **Audit Logging**: FAILED → PASSED
- **Overall Score**: Major improvement in security compliance

---

## 🛠️ Implementation Priority Order

1. **SSH Security Hardening** (CRITICAL - implement immediately)
2. **Hardware RNG Entropy** (HIGH - needed for crypto security)
3. **CAAM Crypto Acceleration** (HIGH - performance and security)
4. **Audit Logging** (MEDIUM - compliance requirement)
5. **Certificate Monitoring** (MEDIUM - operational security)

## 🎯 Quick Implementation Script

For rapid deployment of critical fixes:

```bash
#!/bin/bash
# Quick security fixes implementation

# 1. Add to your meta-subscriber-overrides/recipes-samples/images/lmp-factory-image.bbappend
cat >> lmp-factory-image.bbappend << 'EOF'
# Critical security fixes
IMAGE_INSTALL:append:imx93-jaguar-eink = " \
    rng-tools \
    audit \
    logrotate \
"

# Enable services
SYSTEMD_AUTO_ENABLE:pn-rng-tools = "enable"
SYSTEMD_AUTO_ENABLE:pn-audit = "enable"
EOF

# 2. SSH hardening (requires manual openssh recipe creation)
echo "Remember to create SSH hardening recipe as detailed above"

# 3. CAAM crypto (requires kernel config changes)
echo "Remember to enable CAAM in kernel config as detailed above"
```

This comprehensive security improvement plan addresses the most critical vulnerabilities identified by the security compliance CLI and provides a clear path to production-ready security posture.
