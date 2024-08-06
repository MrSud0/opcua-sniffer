import argparse
import pyshark
import logging

# Configure logging
logger = logging.getLogger("OPCUASniffer")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
logger.propagate = False

# Separator to visually distinguish sections in the logs
PACKET_SEPARATOR = "========================================"

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
    logger.info(f"Packet {packet_number}:")
    logger.debug(f"Packet {packet_number}: Extracting OPC UA info")
    try:
        if 'opcua' in packet:
            opcua_layer = packet.opcua
            if verbosity_level >= 1:
                logger.info(f"Packet {packet_number}: START Analysis of OPCUA fields")
                logger.info(f"Packet {packet_number}: {print_analysis_of_opcua(opcua_layer)}")
                logger.info(f"Packet {packet_number}: {opcua_layer}")
                logger.info(f"Packet {packet_number}: END Analysis of OPCUA fields")
            if verbosity_level >= 2:
                logger.info(f"Packet {packet_number}: START Analysis of the whole packet")
                logger.info(f"Packet {packet_number}: {packet}")
                logger.info(f"Packet {packet_number}: END Analysis of the whole packet")
            return opcua_layer
    except Exception as e:
        logger.error(f"Packet {packet_number}: Error processing packet: {e}")

def mine_security(opcua_layer, packet_number: int) -> None:
    """Mines security-related information from the OPC UA layer."""
    logger.info(f"Packet {packet_number}:")
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

def mine_read_response(opcua_layer, packet_number: int) -> None:
    """Mines read response information from the OPC UA layer."""
    logger.info(f"Packet {packet_number}:")
    logger.info(f"Packet {packet_number}: Mining read response information")
    try:
        if hasattr(opcua_layer, 'datavalue_has_value') and opcua_layer.datavalue_has_value == "True":
            logger.info(f"Packet {packet_number}: Read Value: {opcua_layer.int64}")
    except Exception as e:
        logger.error(f"Packet {packet_number}: Error processing packet: {e}")

def mine_write_request(opcua_layer, packet_number: int) -> None:
    """Mines write request information from the OPC UA layer."""
    logger.info(f"Packet {packet_number}:")
    logger.info(f"Packet {packet_number}: Mining write request information")
    try:
        if hasattr(opcua_layer, 'int64'):
            logger.info(f"Packet {packet_number}: Write Value: {opcua_layer.int64}")
    except Exception as e:
        logger.error(f"Packet {packet_number}: Error processing packet: {e}")

def handle_packet(opcua_layer, packet_number: int) -> None:
    """Handles the packet by calling the appropriate handler based on the service ID."""
    if hasattr(opcua_layer, 'servicenodeid_numeric'):
        service_id = getattr(opcua_layer, 'servicenodeid_numeric')
        handler = SERVICE_HANDLERS.get(service_id)
        if handler:
            handler(opcua_layer, packet_number)
        else:
            logger.info(f"Packet {packet_number}: Unhandled service ID: {service_id}")

SERVICE_HANDLERS = {
    '634': mine_read_response,
    '673': mine_write_request,
    '467': mine_security
}

def main() -> None:
    parser = argparse.ArgumentParser(description="OPC UA Packet Sniffer")
    parser.add_argument("--interface", type=str, required=True, help="Network interface to listen on")
    parser.add_argument("--port", type=int, required=True, help="Port to listen on")
    parser.add_argument("--tshark-path", type=str, default="C:\\temp\\WiresharkPortable64\\App\\Wireshark\\tshark.exe", help="Path to TShark executable")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level (-v for OPC UA layer, -vv for full packet details)")
    parser.add_argument("--no-security", action="store_true", help="Disable security mode (enabled by default)")

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info(f"Starting packet sniffer on interface {args.interface}, port {args.port} using TShark at {args.tshark_path}...")

    capture = pyshark.LiveCapture(interface=args.interface, bpf_filter=f"tcp port {args.port}", tshark_path=args.tshark_path)

    packet_number = 0
    for packet in capture.sniff_continuously():
        packet_number += 1
        logger.info(f"{PACKET_SEPARATOR} Packet {packet_number} {PACKET_SEPARATOR}")
        opcua_layer = extract_opcua_info(packet, args.verbose, packet_number)
        if opcua_layer:
            handle_packet(opcua_layer, packet_number)

if __name__ == "__main__":
    main()
