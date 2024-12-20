import socket
import struct
import textwrap
from datetime import datetime
from scapy.all import *
import re
from urllib.parse import unquote

TAB_1 = '    '
TAB_2 = '        '
TAB_3 = '            '
TAB_4 = '                '

DATA_TAB_1 = '        '
DATA_TAB_2 = '            '
DATA_TAB_3 = '                '
DATA_TAB_4 = '                    '

XSS_PAYLOADS_FILE = "/home/mudasir/Downloads/Moosa-s-Project-main/CODE/XSS_Payloads.txt"

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    interface = "wlan0"
    connection.bind((interface, 0))

    while True:
        raw_data, addr = connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:  # IPv4
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)

            if proto == 6:  # TCP
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload) = tcp_segment(data)

                if dest_port == 80:
                    (request_method, url, http_version, headers, decoded_payload) = http_segment(data)
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTTP {src}:{src_port} ==> {target}:{dest_port}")
                    print(TAB_1, f"- Source MAC: {src_mac}, Destination MAC: {dest_mac}")
                    print(TAB_2 + ' - TCP Segment:')
                    print(TAB_3 + '   - Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB_3 + '   - Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                    print(TAB_3 + '   - Flags:')
                    print(TAB_4 + '     - URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                    print(TAB_2 + '   - Request Method: {}, URL: {}, HTTP Version: {}'.format(request_method, url, http_version))
                    print(TAB_2 + '   - Headers:')
                    print(format_multi_line(DATA_TAB_3, headers))
                    print(TAB_2 + '   - Payload:')
                    print(format_multi_line(DATA_TAB_3, decoded_payload))
                    if detect_xss(decoded_payload):
                        print("\033[91m XSS Detected \033[00m")
                        log_xss_payload(decoded_payload)

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
    request_method = data[:data.find(b' ')]
    url = data[data.find(b' ')+1:data.find(b'HTTP/')]
    http_version = data[data.find(b'HTTP/')+5:data.find(b'\r\n')]
    end_of_headers = data.find(b'\r\n\r\n')
    headers = data[len(request_method) + len(b' ') + len(url) + len(b' ') + len(b'HTTP/') + len(http_version) + len(b'\r\n'):end_of_headers]
    payload = data[end_of_headers + len(b'\r\n\r\n'):]
    decoded_payload = payload.decode('iso-8859-1')
    return request_method.decode('iso-8859-1'), url.decode('iso-8859-1'), http_version.decode('iso-8859-1'), headers.decode('iso-8859-1'), decoded_payload

def detect_xss(payload):
    decoded_payload = unquote_payload(payload)
    xss_patterns = load_xss_patterns()

    for pattern in xss_patterns:
        if pattern.search(decoded_payload):
            return True
    
    return False

def unquote_payload(payload, num_iterations=2):
    decoded_payload = payload
    for _ in range(num_iterations):
        decoded_payload = unquote(decoded_payload)
    return decoded_payload

def load_xss_patterns():
    with open(XSS_PAYLOADS_FILE, 'r') as f:
        xss_payloads = f.read().splitlines()
    
    patterns = []
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
    
    return patterns

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r' {:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join(prefix + line for line in textwrap.wrap(string, size))

def log_xss_payload(payload):
    with open("xss_detected.log", "a") as f:
        f.write(f"XSS Detected: {payload}\n")

if __name__ == '__main__':
    main()
