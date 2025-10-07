# Serial Communication Setup

The Security Compliance CLI now supports serial communication for testing embedded devices that don't have network connectivity.

## Quick Start

### Command Line Usage

```bash
# Basic serial connection
./security-compliance-cli --serial-device /dev/ttyUSB1 test

# Serial with custom settings
./security-compliance-cli \
  --serial-device /dev/ttyUSB0 \
  --baud-rate 9600 \
  --timeout 10 \
  --serial-username root \
  --serial-password mypassword \
  test --test-suite hardware

# Serial with custom prompts
./security-compliance-cli \
  --serial-device COM3 \
  --serial-shell-prompt "$ " \
  --serial-login-prompt "Username:" \
  --serial-password-prompt "Pass:" \
  test
```

### Configuration File Usage

Create a `serial-config.toml` file:

```toml
[communication]
channel_type = "serial"
serial_device = "/dev/ttyUSB1"
baud_rate = 115200
timeout = 10
serial_username = "root"
serial_password = "password"
serial_login_prompt = "login:"
serial_password_prompt = "Password:"
serial_shell_prompt = "# "

[output]
format = "human"
verbose = 2

[tests]
suite = "hardware"
mode = "pre-production"
```

Then run:
```bash
./security-compliance-cli -c serial-config.toml test
```

## Serial Connection Options

| Option | Description | Default |
|--------|-------------|---------|
| `--serial-device` | Serial device path (e.g., `/dev/ttyUSB0`, `COM1`) | Required |
| `--baud-rate` | Serial baud rate | `115200` |
| `--timeout` | Connection timeout in seconds | `30` |
| `--serial-username` | Login username (optional) | None |
| `--serial-password` | Login password (optional) | None |
| `--serial-login-prompt` | Login prompt to wait for | `"login:"` |
| `--serial-password-prompt` | Password prompt to wait for | `"Password:"` |
| `--serial-shell-prompt` | Shell prompt to wait for | `"# "` |

## Device Setup

### Linux
1. Ensure your user is in the `dialout` group:
   ```bash
   sudo usermod -a -G dialout $USER
   ```
2. Log out and back in for the group change to take effect
3. Check available serial devices:
   ```bash
   ls -la /dev/ttyUSB* /dev/ttyACM*
   ```

### Windows
1. Check Device Manager for COM port numbers
2. Use the COM port (e.g., `COM3`, `COM4`) as the device path

### macOS
1. Check available devices:
   ```bash
   ls -la /dev/tty.usb*
   ```

## Troubleshooting

### Device Busy
If you get "Device or resource busy":
```bash
# Check what's using the device
lsof /dev/ttyUSB1

# Kill any processes using the device
sudo fuser -k /dev/ttyUSB1
```

### Permission Denied
```bash
# Check permissions
ls -la /dev/ttyUSB1

# Add user to dialout group
sudo usermod -a -G dialout $USER
```

### Connection Timeout
- Verify the device is connected and powered on
- Check the baud rate matches your device
- Adjust the shell prompt pattern if your device uses a different prompt
- Increase the timeout value for slower devices

## Supported Test Suites

All test suites work with serial communication:
- `hardware` - Hardware security tests
- `boot` - Boot security tests  
- `runtime` - Runtime security tests
- `network` - Network security tests
- `compliance` - Compliance tests
- `all` - All tests

## Examples

### Testing i.MX93 E-Ink Board
```bash
./security-compliance-cli \
  --serial-device /dev/ttyUSB0 \
  --machine imx93-jaguar-eink \
  --serial-username root \
  test --test-suite hardware
```

### Testing with Custom Shell Prompt
```bash
./security-compliance-cli \
  --serial-device /dev/ttyUSB1 \
  --serial-shell-prompt "root@device:~# " \
  test --test-suite compliance
```

### Machine Detection over Serial
```bash
./security-compliance-cli \
  --serial-device /dev/ttyUSB0 \
  detect
```
