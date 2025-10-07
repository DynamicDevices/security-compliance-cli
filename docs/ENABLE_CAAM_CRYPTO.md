# Enable i.MX93 CAAM Crypto Acceleration

## Method 1: Kernel Configuration Fragment

### 1. Create kernel config fragment
Create file: `meta-subscriber-overrides/recipes-kernel/linux/linux-lmp/imx93-caam.cfg`

```
# Enable CAAM (Cryptographic Acceleration and Assurance Module)
CONFIG_CRYPTO_DEV_FSL_CAAM=y
CONFIG_CRYPTO_DEV_FSL_CAAM_JR=y
CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_AHASH_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_RNG_API=y
CONFIG_CRYPTO_DEV_FSL_CAAM_PKC_API=y

# Optional: Enable additional CAAM features
CONFIG_CRYPTO_DEV_FSL_CAAM_INTC=y
CONFIG_CRYPTO_DEV_FSL_CAAM_DEBUG=y
```

### 2. Add fragment to kernel recipe
Create/modify: `meta-subscriber-overrides/recipes-kernel/linux/linux-lmp_%.bbappend`

```bitbake
FILESEXTRAPATHS:prepend := "${THISDIR}/${PN}:"

# Add CAAM configuration fragment for i.MX93
SRC_URI:append:imx93-jaguar-eink = " file://imx93-caam.cfg"
```

## Method 2: Direct Recipe Modification

### Alternative: Modify kernel config directly
In `meta-subscriber-overrides/recipes-kernel/linux/linux-lmp_%.bbappend`:

```bitbake
# Enable CAAM crypto for i.MX93
do_configure:append:imx93-jaguar-eink() {
    echo "CONFIG_CRYPTO_DEV_FSL_CAAM=y" >> ${B}/.config
    echo "CONFIG_CRYPTO_DEV_FSL_CAAM_JR=y" >> ${B}/.config
    echo "CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API=y" >> ${B}/.config
    echo "CONFIG_CRYPTO_DEV_FSL_CAAM_AHASH_API=y" >> ${B}/.config
    echo "CONFIG_CRYPTO_DEV_FSL_CAAM_RNG_API=y" >> ${B}/.config
    echo "CONFIG_CRYPTO_DEV_FSL_CAAM_PKC_API=y" >> ${B}/.config
}
```

## Method 3: Check if CAAM is Available as Module

### First, check if CAAM modules exist but aren't loaded
```bash
# On your development machine, check the kernel source
bitbake -e linux-lmp | grep "^S="
# Then check the kernel config in the source

# Or check if modules exist in staging
find tmp/work/imx93_jaguar_eink-lmp-linux/linux-lmp/ -name "*caam*"
```

## Expected Results After Enabling

After rebuilding and flashing your LMP image, you should see:

### 1. CAAM modules available:
```bash
find /lib/modules/$(uname -r) -name "*caam*"
# Should show:
# /lib/modules/.../kernel/drivers/crypto/caam/caam.ko
# /lib/modules/.../kernel/drivers/crypto/caam/caam_jr.ko
# etc.
```

### 2. CAAM devices in sysfs:
```bash
ls /sys/bus/platform/devices/*caam*
# Should show CAAM platform devices
```

### 3. CAAM in /proc/crypto:
```bash
cat /proc/crypto | grep caam
# Should show CAAM crypto algorithms
```

### 4. Boot messages:
```bash
dmesg | grep caam
# Should show CAAM initialization messages
```

## Quick Test Commands

After enabling CAAM, test with:
```bash
# Load CAAM modules (if built as modules)
modprobe caam
modprobe caam_jr

# Check crypto performance
openssl speed -evp aes-256-cbc
# Should show improved performance with hardware acceleration
```

## Rebuild Process

```bash
# In your Foundries.io build environment
bitbake linux-lmp -c cleansstate
bitbake linux-lmp
bitbake lmp-factory-image

# Flash the new image to your device
```
