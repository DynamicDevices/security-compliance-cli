# Enable Audit Logging for Security Compliance

## 🔍 What the Audit Test Checks

The security compliance test looks for these audit logging features:

1. **auditd service** - Linux audit daemon running
2. **systemd-journal** - Journal logging with disk usage
3. **log rotation** - Logrotate configurations (>2 configs)
4. **security events** - Recent security/auth events in logs

**Scoring:**
- ✅ **PASSED**: 3+ features active
- ⚠️ **WARNING**: 2 features active  
- ❌ **FAILED**: <2 features active (current status)

## 🛠️ Solution: Enable Audit Logging in LMP

### Method 1: Add Audit Package (Recommended)

Add to your `meta-subscriber-overrides/recipes-samples/images/lmp-factory-image.bbappend`:

```bitbake
# Enable comprehensive audit logging
IMAGE_INSTALL:append:imx93-jaguar-eink = " \
    audit \
    logrotate \
"

# Enable audit service by default
SYSTEMD_AUTO_ENABLE:pn-audit = "enable"
```

### Method 2: Comprehensive Logging Setup

For more complete logging, add these packages:

```bitbake
# Comprehensive audit and logging setup
IMAGE_INSTALL:append:imx93-jaguar-eink = " \
    audit \
    logrotate \
    rsyslog \
    systemd-analyze \
"

# Enable services
SYSTEMD_AUTO_ENABLE:pn-audit = "enable"
SYSTEMD_AUTO_ENABLE:pn-rsyslog = "enable"
```

### Method 3: Custom Audit Configuration

Create custom audit rules by adding a recipe:

**File:** `meta-subscriber-overrides/recipes-support/audit/audit_%.bbappend`

```bitbake
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI:append = " file://audit.rules"

do_install:append() {
    install -d ${D}${sysconfdir}/audit/rules.d
    install -m 0640 ${WORKDIR}/audit.rules ${D}${sysconfdir}/audit/rules.d/10-security.rules
}
```

**File:** `meta-subscriber-overrides/recipes-support/audit/files/audit.rules`

```bash
# Security audit rules for embedded systems
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity

# Monitor authentication
-w /var/log/auth.log -p wa -k authentication
-w /var/log/secure -p wa -k authentication

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change

# Monitor network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale

# Monitor file system mounts
-a always,exit -F arch=b64 -S mount -k mounts
```

## 📋 Logrotate Configuration

The test expects >2 logrotate configurations. Add custom logrotate configs:

**File:** `meta-subscriber-overrides/recipes-extended/logrotate/logrotate_%.bbappend`

```bitbake
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI:append = " \
    file://audit.logrotate \
    file://security.logrotate \
"

do_install:append() {
    install -m 644 ${WORKDIR}/audit.logrotate ${D}${sysconfdir}/logrotate.d/audit
    install -m 644 ${WORKDIR}/security.logrotate ${D}${sysconfdir}/logrotate.d/security
}
```

**File:** `meta-subscriber-overrides/recipes-extended/logrotate/files/audit.logrotate`

```
/var/log/audit/*.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        /sbin/service auditd restart > /dev/null 2>&1 || true
    endscript
}
```

**File:** `meta-subscriber-overrides/recipes-extended/logrotate/files/security.logrotate`

```
/var/log/security.log {
    weekly
    rotate 8
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
```

## 🔧 systemd Journal Configuration

Ensure journal logging is properly configured:

**File:** `meta-subscriber-overrides/recipes-core/systemd/systemd_%.bbappend`

```bitbake
FILESEXTRAPATHS:prepend := "${THISDIR}/files:"

SRC_URI:append = " file://journald.conf"

do_install:append() {
    install -m 644 ${WORKDIR}/journald.conf ${D}${sysconfdir}/systemd/journald.conf
}
```

**File:** `meta-subscriber-overrides/recipes-core/systemd/files/journald.conf`

```ini
[Journal]
Storage=persistent
Compress=yes
Seal=yes
SplitMode=uid
SyncIntervalSec=5m
RateLimitInterval=30s
RateLimitBurst=1000
SystemMaxUse=500M
SystemKeepFree=100M
SystemMaxFileSize=50M
RuntimeMaxUse=100M
RuntimeKeepFree=50M
RuntimeMaxFileSize=10M
MaxRetentionSec=1month
MaxFileSec=1week
ForwardToSyslog=no
ForwardToKMsg=no
ForwardToConsole=no
ForwardToWall=yes
```

## ✅ Expected Results After Implementation

After rebuilding and flashing your LMP image, the audit test should show:

### 1. auditd service active:
```bash
systemctl is-active auditd
# Should return: active
```

### 2. Journal with disk usage:
```bash
journalctl --disk-usage
# Should show: Archived and active journals take up XMB in the file system.
```

### 3. Multiple logrotate configs:
```bash
ls -la /etc/logrotate.d/ | wc -l
# Should return: >2 (excluding . and ..)
```

### 4. Security events being logged:
```bash
journalctl --since='1 hour ago' | grep -i 'security\|auth\|fail'
# Should show recent security-related log entries
```

## 📊 Test Status Improvement

After implementation:
- **Before**: ❌ FAILED - "Insufficient audit logging"
- **After**: ✅ PASSED - "Audit logging comprehensive: ['auditd', 'systemd-journal', 'log rotation', 'security events']"

## 🚀 Quick Start (Minimal Setup)

For the fastest implementation, just add this to your image recipe:

```bitbake
IMAGE_INSTALL:append:imx93-jaguar-eink = " audit logrotate"
SYSTEMD_AUTO_ENABLE:pn-audit = "enable"
```

This should be sufficient to get the audit test to pass!

## 🔍 Verification Commands

After deployment, verify with:

```bash
# Check audit service
systemctl status auditd

# Check journal
journalctl --disk-usage

# Check logrotate
ls /etc/logrotate.d/

# Check recent security events
journalctl --since='1 hour ago' | grep -i security

# Test the security CLI
./security-compliance-cli test --test-suite compliance --host <target-ip>
```
