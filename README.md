# opcua-sniffer
Certainly! Below is a `README.md` file that you can use for your GitHub repository:

```markdown
# OPC UA Packet Sniffer

This project is a Python script that sniffs OPC UA packets on a specified network interface and port, and logs various types of information from these packets. The script uses `pyshark` to capture packets and `logging` for output. 

## Features

- Captures OPC UA packets on a specified network interface and port.
- Extracts and logs OPC UA information with different verbosity levels.
- Mines security-related information, read responses, and write requests based on service IDs.

## Requirements

- Python 3.6+
- pyshark
- scapy
- Wireshark (with TShark)

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/opcua-sniffer.git
    cd opcua-sniffer
    ```

2. **Set up the Python environment**:
    Create a virtual environment (optional but recommended):
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install the required Python packages**:
    ```sh
    pip install -r requirements.txt
    ```

4. **Install Wireshark**:
    - Download and install Wireshark from [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html).
    - Ensure that TShark is installed and available in your system PATH.

## Usage

Run the script with the required arguments to start sniffing OPC UA packets:

```sh
python opcua_sniffer.py --interface <INTERFACE> --port <PORT> [options]
```

### Arguments

- `--interface`: Network interface to listen on (e.g., "Ethernet").
- `--port`: Port to listen on (e.g., 4840).
- `--tshark-path`: Path to TShark executable (default: `C:\temp\WiresharkPortable64\App\Wireshark\tshark.exe`).
- `-v`, `--verbose`: Increase verbosity level (-v for OPC UA layer, -vv for full packet details).
- `--no-security`: Disable security mode (enabled by default).

### Example

```sh
python opcua_sniffer.py --interface "Ethernet" --port 4840 --tshark-path "C:\\Program Files\\Wireshark\\tshark.exe" -v
```

## Logging

Logs are output to the console. Each packet is identified with a unique packet number to distinguish logs clearly. The verbosity level determines the amount of detail in the logs:

- `-v`: Logs OPC UA layer information.
- `-vv`: Logs the entire packet information.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```

### Save the above content to a file named `README.md` in your repository.

### Explanation:

- **Title and Description**: Briefly describes the project and its features.
- **Requirements**: Lists the required software and libraries.
- **Installation**: Provides step-by-step instructions to set up the project.
- **Usage**: Explains how to run the script with examples.
- **Arguments**: Details the script's command-line arguments.
- **Logging**: Describes the logging mechanism and verbosity levels.
- **Contributing**: Invites contributions and references the license.
