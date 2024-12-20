import socket
import struct
import textwrap
from datetime import datetime
from scapy.all import *
import re
from urllib.parse import unquote
import threading
import time
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

# Load XSS patterns into memory at startup
XSS_PATTERNS = None

# Thread-safe print
print_lock = threading.Lock()

def main():
    try:
        global XSS_PATTERNS
        XSS_PATTERNS = load_xss_patterns()

        connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        connection.bind((INTERFACE, 0))

        print(f"Listening on {INTERFACE}...")

        while True:
            raw_data, addr = connection.recvfrom(65536)
            threading.Thread(target=process_packet, args=(raw_data,)).start()
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        with print_lock:
            print(f"Error: {e}")

def process_packet(raw_data):
    try:
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:  # IPv4
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

            if proto == 6:  # TCP
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload) = tcp_segment(data)

                if dest_port == 80:  # HTTP Traffic
                    try:
                        (request_method, url, http_version, headers, decoded_payload) = http_segment(data)
                        with print_lock:
                            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTTP {src}:{src_port} ==> {target}:{dest_port}")
                            print(TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}")
                            print(TAB_2 + ' - TCP Segment:')
                            print(TAB_3 + f"   - Source Port: {src_port}, Destination Port: {dest_port}")
                            print(TAB_3 + f"   - Sequence: {sequence}, Acknowledgment: {acknowledgment}")
                            print(TAB_3 + '   - Flags:')
                            print(TAB_4 + f"     - URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, FIN: {flag_fin}")
                            print(TAB_2 + f"   - Request Method: {request_method}, URL: {url}, HTTP Version: {http_version}")
                            print(TAB_2 + '   - Headers:')
                            print(format_multi_line(DATA_TAB_3, headers))
                            print(TAB_2 + '   - Payload:')
                            print(format_multi_line(DATA_TAB_3, decoded_payload))

                        if detect_xss(decoded_payload):
                            with print_lock:
                                print("\033[91mXSS Detected\033[00m")
                            log_xss_payload(decoded_payload)

                    except Exception as e:
                        with print_lock:
                            print(f"Error processing HTTP packet: {e}")
    except Exception as e:
        with print_lock:
            print(f"Error processing packet: {e}")

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def http_segment(data):
    try:
        request_method = data[:data.find(b' ')]
        url = data[data.find(b' ')+1:data.find(b'HTTP/')]
        http_version = data[data.find(b'HTTP/')+5:data.find(b'\r\n')]
        end_of_headers = data.find(b'\r\n\r\n')
        headers = data[len(request_method) + len(b' ') + len(url) + len(b' ') + len(b'HTTP/') + len(http_version) + len(b'\r\n'):end_of_headers]
        payload = data[end_of_headers + len(b'\r\n\r\n'):]

        decoded_payload = payload.decode('iso-8859-1')
        return request_method.decode('iso-8859-1'), url.decode('iso-8859-1'), http_version.decode('iso-8859-1'), headers.decode('iso-8859-1'), decoded_payload
    except Exception as e:
        print(f"Error parsing HTTP segment: {e}")
        return "", "", "", "", ""

def detect_xss(payload):
    decoded_payload = unquote_payload(payload)
    print(f"Decoded Payload: {decoded_payload}")  # Add this line for debugging

    for pattern in XSS_PATTERNS:
        print(f"Checking pattern: {pattern}")  # Debugging line to see which pattern is being checked
        if pattern.search(decoded_payload):
            print(f"XSS Pattern Matched: {pattern} in Payload: {decoded_payload}")  # Debugging line
            return True

    return False

def unquote_payload(payload, num_iterations=2):
    decoded_payload = payload
    for _ in range(num_iterations):
        decoded_payload = unquote(decoded_payload)
    return decoded_payload

def load_xss_patterns():
    patterns = []
    if os.path.exists(XSS_PAYLOADS_FILE):
        with open(XSS_PAYLOADS_FILE, 'r') as f:
            xss_payloads = f.read().splitlines()

        for payload in xss_payloads:
            pattern = re.compile(re.escape(payload), re.IGNORECASE)
            patterns.append(pattern)

    # Add common XSS patterns
    common_patterns = [
        re.compile(r"<script.?>.?</script>", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"vbscript:", re.IGNORECASE),
        re.compile(r"expression\(", re.IGNORECASE),
        re.compile(r"src\s*=\s*[\"'].*?[\"']", re.IGNORECASE),
        re.compile(r"href\s*=\s*[\"'].*?[\"']", re.IGNORECASE),
    ]
    patterns.extend(common_patterns)

    print(f"Loaded XSS Patterns: {len(patterns)}")  # Print the number of patterns loaded

    return patterns

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r' {:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))

def log_xss_payload(payload):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] XSS Detected: {payload}\n")

if __name__ == '__main__':
    main()
