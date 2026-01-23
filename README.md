# OPC UA Packet Sniffer

```
     _ _____             ___            _ 
  __| |___ /_   ___ __  / _ \ _ __ ___ (_)
 / _` | |_ \ \ / / '_ \| | | | '_ ` _ \| |
| (_| |___) \ V /| | | | |_| | | | | | | |
 \__,_|____/ \_/ |_| |_|\___/|_| |_| |_|_|
                                                            
OPC UA Packet Sniffer v2.0 | github.com/d3vn0mi
```

A powerful Python-based packet sniffer for OPC UA (OPC Unified Architecture) protocol traffic. This tool captures and analyzes OPC UA packets on a specified network interface, extracting security credentials, read/write operations, and protocol-level details with configurable verbosity levels and logging options.

## Features

- 🎯 **Smart Packet Analysis**: Captures and dissects OPC UA packets with protocol-aware parsing
- 🔐 **Security Intelligence**: Extracts authentication credentials (usernames, passwords, tokens)
- 📊 **Operation Monitoring**: Tracks read responses and write requests with value extraction
- 📝 **Flexible Logging**: Three verbosity levels with file and console output options
- 🤫 **Silent Mode**: Minimal terminal output with real-time packet counter
- 💾 **Persistent Logs**: Automatic log file generation with immediate flushing
- 🎨 **Professional Interface**: ASCII banner and formatted output
- ⚡ **Real-time Processing**: Live packet capture and analysis
- 🛡️ **Graceful Shutdown**: Proper cleanup and log flushing on exit (Ctrl+C safe)

## What is OPC UA?

OPC UA (OPC Unified Architecture) is an industrial communication protocol used in manufacturing, process control, and building automation. This sniffer helps security professionals analyze OPC UA traffic for:

- Penetration testing and security assessments
- Network traffic analysis
- Credential extraction from insecure implementations
- Protocol debugging and troubleshooting
- Training and security research

## Requirements

- Python 3.6+
- pyshark
- Wireshark (with TShark)
- Root/Administrator privileges (for packet capture)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/d3vhthnnni/opcua-sniffer.git
cd opcua-sniffer
```

### 2. Set Up Python Environment (Recommended)

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Install Wireshark/TShark

#### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install tshark wireshark
```

#### Linux (RedHat/CentOS)
```bash
sudo yum install wireshark
```

#### macOS
```bash
brew install wireshark
```

#### Windows
- Download from [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
- Ensure TShark is in your system PATH or use `--tshark-path` argument

### 5. Grant Capture Permissions (Linux)

```bash
# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# Or run with sudo (not recommended for production)
sudo python opcua_sniffer.py --interface eth0 --port 4840
```

## Usage

### Basic Syntax

```bash
python opcua_sniffer.py --interface <INTERFACE> --port <PORT> [options]
```

### Required Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--interface` | Network interface to capture on | `eth0`, `wlan0`, `"Ethernet"` |
| `--port` | OPC UA port to monitor | `4840` (default OPC UA port) |

### Optional Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--verbosity {1,2,3}` | Verbosity level (1=minimal, 2=normal, 3=debug) | `1` |
| `--silent` | Silent mode - compact counter only in terminal | Disabled |
| `--log-file PATH` | Path to log file | `output.log` (script directory) |
| `--no-log-file` | Disable file logging (console only) | Disabled |
| `--tshark-path PATH` | Path to TShark executable | Auto-detect or default path |
| `--no-security` | Disable security monitoring (not recommended) | Enabled |

## Verbosity Levels

### Level 1 (Default) - Minimal
Shows only packet counter and security events (credentials, tokens).

**Use case**: Long-term monitoring focused on authentication attempts

**Terminal output**:
```
======================================== Packet 1 ========================================
======================================== Packet 2 ========================================
======================================== Packet 3 ========================================
Packet 3: Mining security information
Packet 3: START Security Information
Packet 3:   UserName: admin
Packet 3:   Password: secure123
Packet 3: END Security Information
```

### Level 2 - Normal
Level 1 + read/write operations and service IDs.

**Use case**: General operation monitoring and troubleshooting

**Additional output**:
```
Packet 4: Identified service ID: 634
Packet 4: Mining read response information
Packet 4: Read Value: 42

Packet 5: Identified service ID: 673
Packet 5: Mining write request information
Packet 5: Write Value: 100
```

### Level 3 - Debug
Level 2 + full OPC UA field analysis and complete packet dumps.

**Use case**: Deep protocol analysis and debugging

**Additional output**:
```
Packet 6: START Analysis of OPCUA fields
Packet 6: {'servicenodeid_numeric': '634', 'security_tokenid': '12345', ...}
Packet 6: Layer OPCUA: <complete layer details>
Packet 6: END Analysis of OPCUA fields
```

## Silent Mode

Perfect for background monitoring and long-running sessions.

**Features**:
- Minimal terminal output (single line counter)
- Real-time event tracking
- Log file still populated according to verbosity
- Clean status display

**Terminal output**:
```
Silent mode enabled - only showing packet counter
Log file: /home/user/opcua_sniffer/output.log
------------------------------------------------------------
Packets:    142 | Security:    3 | Reads:   67 | Writes:   28
```

The counter updates in real-time showing:
- **Packets**: Total OPC UA packets processed
- **Security**: Authentication/security events (Service ID 467)
- **Reads**: Read response operations (Service ID 634)
- **Writes**: Write request operations (Service ID 673)

## Examples

### Basic Monitoring (Default Settings)
```bash
python opcua_sniffer.py --interface eth0 --port 4840
```

### Normal Monitoring with Full Details
```bash
python opcua_sniffer.py --interface eth0 --port 4840 --verbosity 2
```

### Debug Mode with All Packet Information
```bash
python opcua_sniffer.py --interface eth0 --port 4840 --verbosity 3
```

### Silent Mode for Background Monitoring
```bash
python opcua_sniffer.py --interface eth0 --port 4840 --silent --verbosity 2
```

### Custom Log File Location
```bash
python opcua_sniffer.py --interface eth0 --port 4840 --log-file /var/log/opcua/capture.log
```

### Console Only (No Log File)
```bash
python opcua_sniffer.py --interface eth0 --port 4840 --no-log-file
```

### Windows with Portable Wireshark
```cmd
python opcua_sniffer.py --interface "Ethernet" --port 4840 --tshark-path "C:\Tools\WiresharkPortable\App\Wireshark\tshark.exe"
```

### Background Process with tmux
```bash
# Start in tmux session
tmux new -s opcua-monitor
python opcua_sniffer.py --interface eth0 --port 4840 --silent --verbosity 2

# Detach: Ctrl+B, then D
# Reattach anytime: tmux attach -t opcua-monitor
```

### Background Process with nohup
```bash
nohup python opcua_sniffer.py --interface eth0 --port 4840 --silent --verbosity 2 &

# Check logs
tail -f output.log

# Stop the process
kill $(pgrep -f opcua_sniffer.py)
```

## Log Files

### Automatic Logging
By default, all output is logged to `output.log` in the same directory as the script.

### Log File Behavior
- **Immediate flushing**: Logs written in real-time (no buffering)
- **Append mode**: New sessions append to existing log
- **UTF-8 encoding**: Handles special characters in credentials
- **Verbosity-aware**: File logging respects verbosity level settings
  - Levels 1-2: INFO messages only
  - Level 3: All DEBUG messages included
- **Graceful shutdown**: Proper log flushing on Ctrl+C or kill signal

### Viewing Logs
```bash
# Follow log in real-time
tail -f output.log

# View last 50 lines
tail -50 output.log

# Search for passwords
grep "Password:" output.log

# Search for specific username
grep "UserName: admin" output.log
```

## Service ID Reference

The sniffer recognizes these OPC UA service IDs:

| Service ID | Type | Description | Verbosity Level |
|------------|------|-------------|-----------------|
| 467 | Security | Authentication, credentials, tokens | 1+ |
| 634 | Read Response | Read operation results and values | 2+ |
| 673 | Write Request | Write operation requests and values | 2+ |

## Security Considerations

### ⚠️ Legal and Ethical Use Only

This tool is designed for:
- ✅ Authorized penetration testing
- ✅ Security assessments with permission
- ✅ Network troubleshooting and debugging
- ✅ Research and training in controlled environments

**DO NOT USE** for:
- ❌ Unauthorized network monitoring
- ❌ Intercepting traffic without permission
- ❌ Any illegal activities

### Best Practices

1. **Always get written permission** before monitoring network traffic
2. **Secure your log files** - they may contain credentials
3. **Use encrypted storage** for logs containing sensitive data
4. **Delete logs** when analysis is complete
5. **Follow responsible disclosure** if vulnerabilities are found

## Troubleshooting

### TShark Not Found
```bash
# Linux: Install and verify
which tshark
sudo apt-get install tshark

# Windows: Specify full path
python opcua_sniffer.py --interface "Ethernet" --port 4840 --tshark-path "C:\Program Files\Wireshark\tshark.exe"
```

### Permission Denied
```bash
# Linux: Add user to wireshark group
sudo usermod -a -G wireshark $USER
# Log out and back in for changes to take effect

# Or run with sudo (temporary)
sudo python opcua_sniffer.py --interface eth0 --port 4840
```

### No Packets Captured
1. Verify interface name: `ip link show` (Linux) or `ipconfig` (Windows)
2. Confirm OPC UA traffic is on the specified port
3. Check firewall rules aren't blocking capture
4. Ensure TShark has proper permissions

### Log File Not Created
1. Check script directory permissions
2. Verify disk space availability
3. Use `--log-file` with explicit path
4. Check for error messages in terminal

## Advanced Usage

### Combining with Other Tools

**Filter logs with grep**:
```bash
tail -f output.log | grep --color=auto "Password\|UserName"
```

**Monitor specific events**:
```bash
tail -f output.log | grep "Security Information"
```

**Count operations**:
```bash
grep "Read Value:" output.log | wc -l
grep "Write Value:" output.log | wc -l
```

### Custom Analysis Scripts

The log format is designed for easy parsing:
```python
import re

with open('output.log', 'r') as f:
    for line in f:
        if 'UserName:' in line:
            username = re.search(r'UserName: (.+)', line).group(1)
            print(f"Found username: {username}")
```

## Output Format

### Log Entry Structure
```
TIMESTAMP - LOGGER_NAME - LEVEL - MESSAGE
```

Example:
```
2026-01-23 10:00:01 - OPCUASniffer - INFO - ======================================== Packet 1 ========================================
2026-01-23 10:00:02 - OPCUASniffer - INFO - Packet 3: UserName: admin
```

## Contributing

Contributions are welcome! Here's how you can help:

1. 🐛 **Report bugs**: Open an issue with details and reproduction steps
2. 💡 **Suggest features**: Share your ideas for improvements
3. 🔧 **Submit PRs**: Fix bugs or add features (please follow existing code style)
4. 📖 **Improve docs**: Help make the documentation clearer
5. ⭐ **Star the repo**: Show your support!

### Development Setup
```bash
git clone https://github.com/d3vhthnnni/opcua-sniffer.git
cd opcua-sniffer
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this program. Always ensure you have explicit permission before monitoring network traffic.

## Author

**d3vhthnnni**
- GitHub: [@d3vhthnnni](https://github.com/d3vhthnnni)

## Acknowledgments

- Built with [PyShark](https://github.com/KimiNewt/pyshark)
- Uses [Wireshark](https://www.wireshark.org/) TShark for packet capture
- OPC UA protocol specification by the [OPC Foundation](https://opcfoundation.org/)

## Version History

### v2.0 (Current)
- ✨ Added ASCII banner with branding
- ✨ Implemented silent mode with real-time counter
- ✨ Added three-level verbosity system (1-3)
- ✨ File logging with configurable path
- ✨ Immediate log flushing for real-time analysis
- ✨ Graceful shutdown handling
- ✨ Event tracking (security, reads, writes)
- 🔧 Replaced `-v`/`-vv` with `--verbosity {1,2,3}`
- 🔧 Improved error handling and cleanup
- 📝 Comprehensive documentation

### v1.0
- Initial release
- Basic OPC UA packet capture
- Security information extraction
- Read/write operation monitoring

---

**⚠️ Remember**: Always use this tool responsibly and with proper authorization. Network monitoring without permission may be illegal in your jurisdiction.