import socket
import struct
import textwrap
from datetime import datetime
from scapy.all import *
import re
from urllib.parse import unquote
import threading
import os

# Constants
TAB_1 = '    '
TAB_2 = '        '
TAB_3 = '            '
TAB_4 = '                '
DATA_TAB_1 = '        '
DATA_TAB_2 = '            '
DATA_TAB_3 = '                '
DATA_TAB_4 = '                    '

XSS_PAYLOADS_FILE = "/home/mudasir/Projects/MyIDS/XSS_Payloads.txt"
LOG_FILE = "xss_detected.log"
INTERFACE = "wlan0"

# Global XSS patterns loaded at startup
XSS_PATTERNS = []

# Thread-safe print
print_lock = threading.Lock()

def main():
    """Main entry point for the script."""
    try:
        load_xss_patterns()

        # Open a raw socket for capturing packets
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) as connection:
            connection.bind((INTERFACE, 0))
            print(f"Listening on interface: {INTERFACE}")

            while True:
                raw_data, _ = connection.recvfrom(65536)
                threading.Thread(target=process_packet, args=(raw_data,)).start()
    except KeyboardInterrupt:
        print("\nExiting gracefully...")
    except Exception as e:
        with print_lock:
            print(f"Error: {e}")

def process_packet(raw_data):
    """Processes individual packets."""
    try:
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:  # IPv4
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

            if proto == 6:  # TCP
                tcp_header = tcp_segment(data)

                # Check for HTTP traffic (port 80)
                if tcp_header["dest_port"] == 80:
                    handle_http_traffic(src, tcp_header, target, data)
    except Exception as e:
        with print_lock:
            print(f"Error processing packet: {e}")

def handle_http_traffic(src, tcp_header, target, data):
    """Handles HTTP traffic and checks for XSS."""
    try:
        request_method, url, http_version, headers, payload = http_segment(data)
        print_http_details(src, tcp_header, target, request_method, url, http_version, headers, payload)

        if detect_xss(payload):
            with print_lock:
                print("\033[91mXSS Detected!\033[00m")
            log_xss_payload(payload)
    except Exception as e:
        with print_lock:
            print(f"Error processing HTTP traffic: {e}")

def print_http_details(src, tcp_header, target, method, url, version, headers, payload):
    """Prints HTTP details to the console."""
    with print_lock:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTTP {src} ==> {target}")
        print(f"{TAB_1}- Method: {method}, URL: {url}, Version: {version}")
        print(f"{TAB_2}- Headers:")
        print(format_multi_line(DATA_TAB_3, headers))
        print(f"{TAB_2}- Payload:")
        print(format_multi_line(DATA_TAB_3, payload))

def ethernet_frame(data):
    """Parses Ethernet frames."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    """Returns a readable MAC address."""
    return ':'.join(f'{byte:02x}' for byte in bytes_addr).upper()

def ipv4_packet(data):
    """Parses IPv4 packets."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    """Converts raw IP addresses to human-readable format."""
    return '.'.join(map(str, addr))

def tcp_segment(data):
    """Parses TCP segments."""
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "sequence": sequence,
        "acknowledgment": acknowledgment,
        "data_offset": offset,
        "data": data[offset:]
    }

import re

def http_segment(data):
    try:
        # Decode raw data into a string
        decoded_data = data.decode('utf-8', errors='replace')
        
        # Debug: Log decoded data for analysis
        print("Raw HTTP Data:\n", decoded_data)

        # Split headers and payload
        header_end_index = decoded_data.find("\r\n\r\n")
        if header_end_index == -1:
            return "Malformed Data", "Malformed Data", "Malformed Data", "Not Available", "Not Available"

        headers = decoded_data[:header_end_index]
        payload = decoded_data[header_end_index + 4:]  # Skip "\r\n\r\n"

        # Extract the request line (first line of headers)
        header_lines = headers.split("\r\n")
        request_line = header_lines[0] if header_lines else ""
        
        # Debug: Log the request line
        print("Request Line:", request_line)

        # Use regex to extract valid HTTP methods and clean noise
        method_match = re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s", request_line)
        request_method = method_match.group(1) if method_match else "Malformed Data"

        # Extract URL and version (handling malformed data)
        url_version_match = re.match(r"^[A-Z]+\s+(\S+)\s+(HTTP/\d\.\d)", request_line)
        url = url_version_match.group(1) if url_version_match else "Malformed Data"
        http_version = url_version_match.group(2) if url_version_match else "Malformed Data"

        # Debug: Log extracted components
        print(f"Method: {request_method}, URL: {url}, Version: {http_version}")

        # Format headers with proper indentation
        formatted_headers = []
        for line in header_lines[1:]:
            formatted_headers.append(re.sub(r"(.{80})", r"\1\n                \n", line.strip()))
        formatted_headers = "\n                ".join(formatted_headers)

        # Return parsed components
        return (
            request_method,
            url,
            http_version,
            formatted_headers.strip(),
            payload.strip() or "Not Available"
        )
    except Exception as e:
        print(f"Error parsing HTTP segment: {e}")
        return "Error", "Error", "Error", "Error", "Error"

def detect_xss(payload):
    """Detects potential XSS in HTTP payloads."""
    decoded_payload = unquote_payload(payload)
    for pattern in XSS_PATTERNS:
        if pattern.search(decoded_payload):
            return True
    return False

def unquote_payload(payload, num_iterations=2):
    """Decodes URL-encoded payload multiple times."""
    for _ in range(num_iterations):
        payload = unquote(payload)
    return payload

def load_xss_patterns():
    """Loads XSS patterns from file and common patterns."""
    global XSS_PATTERNS
    if os.path.exists(XSS_PAYLOADS_FILE):
        with open(XSS_PAYLOADS_FILE, 'r') as f:
            patterns = [re.compile(re.escape(line.strip()), re.IGNORECASE) for line in f]
            XSS_PATTERNS.extend(patterns)

    # Add common XSS patterns
    XSS_PATTERNS.extend([
        re.compile(r"<script.*?>.*?</script>", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"vbscript:", re.IGNORECASE),
        re.compile(r"expression\(", re.IGNORECASE),
        re.compile(r"src\s*=\s*[\"'].*?[\"']", re.IGNORECASE),
        re.compile(r"href\s*=\s*[\"'].*?[\"']", re.IGNORECASE),
    ])
    print(f"Loaded {len(XSS_PATTERNS)} XSS patterns.")

def format_multi_line(prefix, string, size=80):
    """Formats strings with multi-line indentation."""
    size -= len(prefix)
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))

def log_xss_payload(payload):
    """Logs detected XSS payloads."""
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] XSS Detected: {payload}\n")

if __name__ == '__main__':
    main()
