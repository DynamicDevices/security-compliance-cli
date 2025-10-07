# Security Compliance Fixes for Foundries.io LMP

## 🔥 Priority 1: Hardware RNG Entropy Fix

### Problem
- Current entropy: 256 bits (insufficient)
- ELE-TRNG hardware working but not fed into kernel pool
- Missing `rngd` daemon to bridge hardware RNG to kernel

### Solution
Add to your `meta-subscriber-overrides/recipes-samples/images/lmp-factory-image.bbappend`:

```bitbake
# Fix hardware RNG entropy
IMAGE_INSTALL:append:imx93-jaguar-eink = " rng-tools"

# Alternative: haveged for additional entropy
# IMAGE_INSTALL:append:imx93-jaguar-eink = " haveged"
```

### Expected Result
- Entropy will increase from 256 to 1000+ bits
- Hardware RNG test will change from FAILED to PASSED
- Improved crypto performance and security

---

## 🔥 Priority 2: i.MX93 CAAM Crypto Acceleration

### Problem
- Hardware crypto acceleration not detected
- Missing CAAM (Cryptographic Acceleration and Assurance Module)
- Crypto operations running in software only

### Solution
Ensure these are enabled in your kernel config:

```
CONFIG_CRYPTO_DEV_FSL_CAAM=y
CONFIG_CRYPTO_DEV_FSL_CAAM_JR=y
CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_AHASH_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_RNG_API=y
```

Add CAAM modules to your image:
```bitbake
IMAGE_INSTALL:append:imx93-jaguar-eink = " kernel-module-caam kernel-module-caam-jr"
```

### Expected Result
- Hardware crypto acceleration test will change from FAILED to PASSED
- Significant crypto performance improvement
- Enhanced security through hardware-backed operations

---

## 📋 Priority 3: Audit Logging

### Problem
- No audit daemon running
- Cannot track security events
- Compliance requirement not met

### Solution
```bitbake
IMAGE_INSTALL:append:imx93-jaguar-eink = " audit"

# Enable audit service
SYSTEMD_AUTO_ENABLE:pn-audit = "enable"
```

### Expected Result
- Audit logging test will change from FAILED to PASSED
- Security events will be tracked and logged
- Compliance requirements met

---

## ⚠️ Firewall Configuration (Pre-production vs Production)

### Current Status
- **Pre-production**: Firewall not configured (expected behavior)
- **Production**: Firewall configured during deployment

### Note
This is not an issue for pre-production testing. The firewall test should be enhanced to be mode-aware:
- **Pre-production mode**: Should show WARNING instead of FAILED
- **Production mode**: Should require firewall configuration

### Future Enhancement
Update the firewall test to handle testing modes appropriately.

---

## 📋 Priority 4: Certificate Monitoring

### Problem
- No certificate expiration monitoring
- Risk of expired certificates

### Solution
Create monitoring script or add:
```bitbake
IMAGE_INSTALL:append:imx93-jaguar-eink = " certwatch"
```

---

## 🚫 Container Security (Optional)

The container security failures can be ignored if you're not using containers:
- `container_001`, `container_004`, `container_005`, `container_007`

If not using containers, consider adding this to your test config to skip container tests:
```toml
[tests]
suite = "boot,runtime,hardware,network,compliance,certificate"  # Skip container tests
```

---

## 📊 Expected Improvement

After implementing these fixes:
- **Success Rate**: Should improve from 23.9% to ~65%+
- **Critical Issues**: Reduced from 10 to ~3
- **Security Posture**: Significantly enhanced
