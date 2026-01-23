import argparse
import pyshark
import logging
import os
import signal
import sys
import atexit

# Banner
BANNER = r"""
     _ _____             ___            _ 
  __| |___ /_   ___ __  / _ \ _ __ ___ (_)
 / _` | |_ \ \ / / '_ \| | | | '_ ` _ \| |
| (_| |___) \ V /| | | | |_| | | | | | | |
 \__,_|____/ \_/ |_| |_|\___/|_| |_| |_|_|
                                                            
OPC UA Packet Sniffer v2.0 | github.com/d3vn0mi
"""

# Configure logging
logger = logging.getLogger("OPCUASniffer")
logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all logs

# Console handler
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)  # Console shows INFO and above by default
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
logger.propagate = False

# Separator to visually distinguish sections in the logs
PACKET_SEPARATOR = "========================================"

def print_banner():
    """Print the banner at startup."""
    print(BANNER)

def print_analysis_of_opcua(layer) -> dict:
    """Extracts all fields and their values in a given layer."""
    return {field: layer.get_field(field) for field in layer.field_names}

def decode_hex_string(hex_string: str) -> str:
    """Decodes a hex-encoded string to a regular string."""
    try:
        bytes_object = bytes.fromhex(hex_string)
        return bytes_object.decode('utf-8')
    except ValueError as e:
        logger.error(f"Failed to decode hex string: {e}")
        return hex_string    

def extract_opcua_info(packet, verbosity_level: int, packet_number: int):
    """Extracts OPC UA layer information based on verbosity level."""
    logger.debug(f"Packet {packet_number}: Extracting OPC UA info")
    try:
        if 'opcua' in packet:
            opcua_layer = packet.opcua
            
            # Level 3: Show full debug information
            if verbosity_level >= 3:
                logger.info(f"Packet {packet_number}: START Analysis of OPCUA fields")
                logger.info(f"Packet {packet_number}: {print_analysis_of_opcua(opcua_layer)}")
                logger.info(f"Packet {packet_number}: {opcua_layer}")
                logger.info(f"Packet {packet_number}: END Analysis of OPCUA fields")
                logger.info(f"Packet {packet_number}: START Analysis of the whole packet")
                logger.info(f"Packet {packet_number}: {packet}")
                logger.info(f"Packet {packet_number}: END Analysis of the whole packet")
            
            return opcua_layer
    except Exception as e:
        logger.error(f"Packet {packet_number}: Error processing packet: {e}")

def mine_security(opcua_layer, packet_number: int, verbosity_level: int = 1) -> None:
    """Mines security-related information from the OPC UA layer. Available at verbosity level 1+"""
    logger.info(f"Packet {packet_number}: Mining security information")
    try:
        logger.info(f"Packet {packet_number}: START Security Information")
        if hasattr(opcua_layer, 'security_tokenid'):
            logger.info(f"Packet {packet_number}:   Security Token ID: {opcua_layer.security_tokenid}")
        if hasattr(opcua_layer, 'security_seq'):
            logger.info(f"Packet {packet_number}:   Security Sequence: {opcua_layer.security_seq}")
        if hasattr(opcua_layer, 'security_rqid'):
            logger.info(f"Packet {packet_number}:   Security Request ID: {opcua_layer.security_rqid}")
        if hasattr(opcua_layer, 'policyid'):
            logger.info(f"Packet {packet_number}:   PolicyId: {opcua_layer.policyid}")
        if hasattr(opcua_layer, 'username'):
            logger.info(f"Packet {packet_number}:   UserName: {opcua_layer.username}")
        if hasattr(opcua_layer, 'password'):
            decoded_password = decode_hex_string(opcua_layer.password.replace(':', ''))
            logger.info(f"Packet {packet_number}:   Password: {decoded_password}")
        logger.info(f"Packet {packet_number}: END Security Information")
    except Exception as e:
        logger.error(f"Packet {packet_number}: Error processing packet: {e}")

def mine_read_response(opcua_layer, packet_number: int, verbosity_level: int = 1) -> None:
    """Mines read response information from the OPC UA layer. Available at verbosity level 2+"""
    if verbosity_level < 2:
        return
    
    logger.info(f"Packet {packet_number}: Mining read response information")
    try:
        if hasattr(opcua_layer, 'datavalue_has_value') and opcua_layer.datavalue_has_value == "True":
            if hasattr(opcua_layer, 'int64'):
                logger.info(f"Packet {packet_number}: Read Value: {opcua_layer.int64}")
            elif hasattr(opcua_layer, 'int32'):
                logger.info(f"Packet {packet_number}: Read Value: {opcua_layer.int32}")
            else:
                logger.info(f"Packet {packet_number}: Read Value: [Unsupported Data Type]")
    except Exception as e:
        logger.error(f"Packet {packet_number}: Error processing packet: {e}")

def mine_write_request(opcua_layer, packet_number: int, verbosity_level: int = 1) -> None:
    """Mines write request information from the OPC UA layer. Available at verbosity level 2+"""
    if verbosity_level < 2:
        return
    
    logger.info(f"Packet {packet_number}: Mining write request information")
    try:
        if hasattr(opcua_layer, 'int64'):
            logger.info(f"Packet {packet_number}: Write Value: {opcua_layer.int64}")
    except Exception as e:
        logger.error(f"Packet {packet_number}: Error processing packet: {e}")

def handle_packet(opcua_layer, packet_number: int, verbosity_level: int = 1) -> None:
    """Handles the packet by calling the appropriate handler based on the service ID."""
    if hasattr(opcua_layer, 'servicenodeid_numeric'):
        service_id = getattr(opcua_layer, 'servicenodeid_numeric')
        handler = SERVICE_HANDLERS.get(service_id)
        
        if verbosity_level >= 2:
            logger.info(f"Packet {packet_number}: Identified service ID: {service_id}")
        
        if handler:
            handler(opcua_layer, packet_number, verbosity_level)
        else:
            if verbosity_level >= 2:
                logger.info(f"Packet {packet_number}: Unhandled service ID: {service_id}")

SERVICE_HANDLERS = {
    '634': mine_read_response,
    '673': mine_write_request,
    '467': mine_security
}

def setup_file_logging(log_file_path: str, verbosity_level: int = 1) -> None:
    """Sets up file logging handler with immediate flushing."""
    try:
        # Create directory if it doesn't exist
        log_dir = os.path.dirname(log_file_path)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Custom handler that flushes after each write
        class FlushFileHandler(logging.FileHandler):
            def emit(self, record):
                super().emit(record)
                self.flush()
        
        # File handler with immediate flushing
        fh = FlushFileHandler(log_file_path, mode='a', encoding='utf-8')
        
        # Set file handler level based on verbosity
        # Level 1-2: INFO and above (filters out DEBUG)
        # Level 3: DEBUG and above (shows everything)
        if verbosity_level >= 3:
            fh.setLevel(logging.DEBUG)
        else:
            fh.setLevel(logging.INFO)
        
        fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        logger.addHandler(fh)
        logger.info(f"Logging to file: {log_file_path} (verbosity level: {verbosity_level})")
    except Exception as e:
        logger.error(f"Failed to set up file logging: {e}")

def cleanup_logging():
    """Ensures all log handlers are flushed and closed properly."""
    # Print newline if we were in silent mode to clean up the terminal
    print()  # Move to next line after counter
    logger.info("Shutting down sniffer...")
    for handler in logger.handlers:
        handler.flush()
        handler.close()

def signal_handler(sig, frame):
    """Handle interrupt signals gracefully."""
    cleanup_logging()
    sys.exit(0)

def main() -> None:
    # Print banner
    print_banner()
    
    # Get the script's directory for default log file path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_log_file = os.path.join(script_dir, "output.log")
    
    parser = argparse.ArgumentParser(
        description="OPC UA Packet Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Verbosity Levels:
  1 (default) - Show packet counter and security information only
  2           - Show level 1 + read responses and write requests
  3           - Show level 2 + full debug information (all OPCUA fields and packet details)

Silent Mode:
  --silent    - Hide all terminal output except compact packet counter
                Log file is still populated according to verbosity level
        """
    )
    parser.add_argument("--interface", type=str, required=True, help="Network interface to listen on")
    parser.add_argument("--port", type=int, required=True, help="Port to listen on")
    parser.add_argument("--tshark-path", type=str, default="C:\\temp\\WiresharkPortable64\\App\\Wireshark\\tshark.exe", help="Path to TShark executable")
    parser.add_argument("--verbosity", type=int, choices=[1, 2, 3], default=1, help="Verbosity level (1=minimal, 2=normal, 3=debug)")
    parser.add_argument("--silent", action="store_true", help="Silent mode - only show compact packet counter in terminal (log file still populated)")
    parser.add_argument("--no-security", action="store_true", help="Disable security mode (enabled by default)")
    parser.add_argument("--log-file", type=str, default=default_log_file, help=f"Path to log file (default: {default_log_file})")
    parser.add_argument("--no-log-file", action="store_true", help="Disable file logging (only output to console)")

    args = parser.parse_args()

    # Register cleanup handlers
    atexit.register(cleanup_logging)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Handle silent mode - disable console output
    if args.silent:
        # Remove console handler to suppress all terminal output
        logger.handlers = [h for h in logger.handlers if not isinstance(h, logging.StreamHandler) or isinstance(h, logging.FileHandler)]
        print("Silent mode enabled - only showing packet counter")
        print("Log file:", args.log_file if not args.no_log_file else "disabled")
        print("-" * 60)
    else:
        # Adjust console handler verbosity - only show DEBUG logs at level 3
        if args.verbosity >= 3:
            for handler in logger.handlers:
                if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                    handler.setLevel(logging.DEBUG)

    # Set up file logging unless disabled
    if not args.no_log_file:
        setup_file_logging(args.log_file, args.verbosity)

    logger.info(f"Starting packet sniffer on interface {args.interface}, port {args.port} using TShark at {args.tshark_path}...")
    logger.info(f"Verbosity level: {args.verbosity}")

    capture = pyshark.LiveCapture(interface=args.interface, bpf_filter=f"tcp port {args.port}", tshark_path=args.tshark_path)

    packet_number = 0
    security_events = 0
    read_events = 0
    write_events = 0
    
    for packet in capture.sniff_continuously():
        packet_number += 1
        
        # Silent mode: show compact counter
        if args.silent:
            print(f"\rPackets: {packet_number:6d} | Security: {security_events:4d} | Reads: {read_events:4d} | Writes: {write_events:4d}", end='', flush=True)
        else:
            # Level 1+: Show packet counter
            logger.info(f"{PACKET_SEPARATOR} Packet {packet_number} {PACKET_SEPARATOR}")
        
        opcua_layer = extract_opcua_info(packet, args.verbosity, packet_number)
        if opcua_layer:
            # Track event types for silent mode counter
            if hasattr(opcua_layer, 'servicenodeid_numeric'):
                service_id = getattr(opcua_layer, 'servicenodeid_numeric')
                if service_id == '467':
                    security_events += 1
                elif service_id == '634':
                    read_events += 1
                elif service_id == '673':
                    write_events += 1
            
            handle_packet(opcua_layer, packet_number, args.verbosity)

if __name__ == "__main__":
    main()
