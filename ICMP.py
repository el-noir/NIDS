import socket
import struct
import textwrap
import datetime
from scapy.layers.inet import IP, ICMP
from scapy.packet import Raw

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

THRESHOULD = 10
MAX_ALLOWED_SIZE = 1473

type_names = {
    0: 'Echo Reply',
    3: 'Time Exceeded',
    4: 'Parameter Problem',
    5: 'Redirect Message',
    8: 'Echo Request',
    11: 'Time-TO-LIVE Exceeded',
    12: 'Address Mask Request',
    13: 'Address Mask Reply',
    14: 'Timestamp',
    15: 'Timestamp Reply',
    16: 'Information Request',
    17: 'Information Reply',
    18: 'Address Mapping',
    19: 'Address Mapping Reply'
}

log_file = '/home/mudasir/Projects/MyIDS/icmp_logs.csv'
timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

attacker_ips = []

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    ip_address_set = set()  # Set to store IP addresses of detected ICMP ping flood attacks
    ip_count_dict = {}
    count = 0
    
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        # ipv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            # ICMP
            if proto == 1:
                icmp_type, code, checksum, identifier, sequence, decoded_payload, type_name = icmp_packet(data)

                print(f"\n[+] ICMP {src} ==> {target}")
                print(TAB_1 + 'Ethernet Frame: ')
                print(TAB_2 + 'Destination: {}, Source: {}'.format(dest_mac, src_mac))
                print(TAB_2 + 'Protocol: {}'.format(eth_proto))
                print(TAB_1 + 'IPv4 Packet: ')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_2 + 'Protocol: {}'.format(proto))
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Identifier: {}, Sequence: {}'.format(identifier, sequence))
                print(TAB_2 + 'Type: {}'.format(type_name))
                print(TAB_2 + 'Payload:')
                print(format_multi_line(DATA_TAB_3, decoded_payload))

                count += 1
                log_icmp(timestamp, src, count, log_file, icmp_type, code, identifier, sequence)
                
                if ping_flood(data, ip_address_set, ip_count_dict):
                    print(f"{TAB_2}\033[91m[##] PING FLOOD DETECTED\033[0m")
                    attacker_ips.append(src)
                    print("\n")

                if ping_death(data, ip_address_set):
                    print(f"{TAB_2}\033[91m[##] PING DEATH DETECTED\033[0m")
                    attacker_ips.append(src)
                    print("\n")

# No block_ip function is used in this version.

# Unchanged functions remain the same...
# unpack ethernet frames, log_icmp, ping_death, etc.


                if detect_icmp_smurf_attack(log_file):
                  print(f"{TAB_2}\033[91m[##] ICMP SMURF ATTACK DETECTED\033[0m")
                  attacker_ips.append(src)
                  block_ip()
                  print("\n")

                if detect_icmp_time_exceeded_attack(log_file):
                  print(f"{TAB_2}\033[91m[##] ICMP TIME EXCEEDED ATTACK DETECTED\033[0m")
                  attacker_ips.append(src)
                  block_ip()
                  print("\n")

                if detect_icmp_destination_unreachable_attack(log_file):
                 print(f"{TAB_2}\033[91m[##] ICMP DESTINATION UNREACHABLE ATTACK DETECTED\033[0m")
                 attacker_ips.append(src)
                 block_ip()
                 print("\n")

                if detect_icmp_redirection_attack(icmp_type, log_file):
                 print(f"{TAB_2}\033[91m[##] ICMP REDIRECTION ATTACK DETECTED\033[0m")
                 attacker_ips.append(src)
                 print("\n")


            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, offset_reserved_flags) = tcp_segment(data)
                

            elif proto == 17:
                #src_port, dest_port, length, data = udp_segment(data)
                number = 0

def block_ip(ip_address):
    try:
        command = ['iptables', '-A', 'INPUT', '-s', ip_address, '-p', 'icmp', '-j', 'DROP']
        print("Executing command:", ' '.join(command))
        subprocess.run(command, check=True)
        print(f"Blocked ICMP traffic from {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block ICMP traffic from {ip_address}: {e}")

# unpack ethernet frames
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# return a properly formatted mac address, i.e. (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


# unpack ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# return a properly formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


# unpack icmp packet
def icmp_packet(data):
    # Check if the packet data length is sufficient for ICMP header
    if len(data) < 12:
        print("Error: Insufficient data length for ICMP header")
        return None, None, None, None, None, None, None

    fields = '! B B H L L'  # b - 1 byte, B - 2 bytes, H - 4 bytes, L - 4 bytes

    try:
        unpacked_data = struct.unpack(fields, data[:12])
    except struct.error:
        print("Error: Failed to unpack ICMP header")
        return None, None, None, None, None, None, None

    icmp_type, code, checksum, identifier, sequence = unpacked_data
    payload = data[8:]  # rest of the packet is payload
    if icmp_type in type_names:
        type_name = type_names[icmp_type]
    else:
        type_name = 'Unknown'

    payload = data[8:12]

    return icmp_type, code, checksum, identifier, sequence, payload, type_name


# unpack tcp segment
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


# format the multi-line data
def format_multi_line(prefix, string, size=80):
    """
    Format the multi-line data.
    :param prefix: The prefix for each line.
    :param string: The string to format.
    :param size: The size of each line.
    :return: The formatted string.
    """
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r' {:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    if string is not None:
        return '\n'.join(prefix + line for line in textwrap.wrap(string, size)
                        if string is not None)
    else:
        return "No payload data"

# Log ICMP details in the specified format.
def log_icmp(timestamp: str, ip_address: str, count: int, log_file: str, icmp_type: str, icmp_code: str, identifier: int, sequence: int) -> None:
    """
    Log ICMP details in the specified format.

    :param timestamp: The timestamp of the log entry.
    :param ip_address: The IP address associated with the log entry.
    :param count: The count of ICMP packets.
    :param packet_type: The type of ICMP packet.
    :param packet_code: The code of ICMP packet.
    :param log_file: The path to the log file.
    :param icmp_type: The type of ICMP packet.
    :param icmp_code: The code of ICMP packet.
    :param identifier: The identifier of ICMP packet.
    :param sequence: The sequence of ICMP packet.
    """
    log_entry = f"{timestamp}, {ip_address}, {count}, {icmp_type}, {icmp_code}, {identifier}, {sequence}\n"

    try:
        with open(log_file, 'a') as f:
            f.write(log_entry)
    except IOError as e:
        print(f"Error writing to log file: {e}")

def ping_death(data, ip_address_set):
    """
    Ping of Death:
    Identification: Detection of ICMP Echo Request packets with sizes exceeding the maximum packet size allowed by the network stack.
    Packet Information: Analyze ICMP Echo Request packets for unusually large sizes that may indicate malformed or oversized packets.

    :param data: The ICMP packet data.
    :param ip_address_set: The set of IP addresses associated with the ICMP packets.
    :return: True if the ICMP packet is a Ping of Death, False otherwise.
    """
    # Check if the packet data length is sufficient for ICMP header
    if len(data) < 20:
        print("Error: Insufficient data length for ICMP header")
        return False

    # Extract the ICMP header
    try:
        icmp_header = data[20:22]
        icmp_type, icmp_code = struct.unpack('BB', icmp_header)
    except struct.error:
        print("Error: Failed to unpack ICMP header")
        return False

    # Check if the ICMP packet size exceeds the maximum allowed size
    if len(data) > MAX_ALLOWED_SIZE:
        return True

    return False

def is_fragmented(data):
    """
    Check if the ICMP packet is fragmented.

    :param data: The ICMP packet data.
    :return: True if the packet is fragmented, False otherwise.
    """
    # Extract the fragmentation offset and more fragments flag from the IP header
    offset, mf_flag = struct.unpack("!HH", data[6:10])
    
    # Check if the more fragments flag is set or the offset is nonzero
    return (offset > 0) or (mf_flag & 0x2000)


def get_network_stack_limit():
    """
    Get the maximum allowed size for an ICMP packet from the network stack.

    :return: Maximum allowed size for an ICMP packet.
    """
    # Implement logic to retrieve the maximum allowed size from the network stack
    return 1472  # Placeholder implementation

#ICMP SMURF Attack
def detect_icmp_smurf_attack(log_file):
    """
    Detect ICMP Smurf Attack from log entries.
    """
    ICMP_SMURF_ATTACK_THRESHOLD = 10
    ICMP_SMURF_ATTACK_WINDOW = 60  # seconds

    broadcast_addresses = ["255.255.255.255", "192.168.1.255"]  # Add other known broadcast addresses as needed
    icmp_activity = {}

    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()

        for line in lines:
            # Parse the log entry
            parts = line.strip().split(", ")
            if len(parts) < 3:
                continue
            timestamp_str, src_ip, count = parts[0], parts[1], int(parts[2])
            timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            if src_ip in broadcast_addresses:
                if src_ip not in icmp_activity:
                    icmp_activity[src_ip] = []

                icmp_activity[src_ip].append(timestamp)

                # Maintain only recent timestamps
                icmp_activity[src_ip] = [
                    ts for ts in icmp_activity[src_ip]
                    if (timestamp - ts).seconds <= ICMP_SMURF_ATTACK_WINDOW
                ]

                # Detect Smurf attack
                if len(icmp_activity[src_ip]) >= ICMP_SMURF_ATTACK_THRESHOLD:
                    return True

    except IOError as e:
        print(f"Error reading log file: {e}")

    return False

def is_fragmented(data):
    """
    Check if the ICMP packet is fragmented.
    :param data: The ICMP packet data.
    :return: True if the packet is fragmented, False otherwise.
    """
    flags_and_fragment_offset = struct.unpack("!H", data[6:8])[0]
    mf_flag = flags_and_fragment_offset & 0x2000  # More Fragments flag
    fragment_offset = flags_and_fragment_offset & 0x1FFF  # Fragment offset
    return mf_flag > 0 or fragment_offset > 0


#PING FLOOD
def ping_flood(data, ip_address_set, ip_count_dict):
    """
    Ping Flood detection

    :param data: The ICMP packet data.
    :param ip_address_set: The set of detected ICMP ping flood IP addresses.
    :param ip_count_dict: A dictionary to store the count for each victim IP address.
    :return: True if a ping flood attack is detected, False otherwise.
    """
    fields = '! B B H L L'  # b - 1 byte, B - 2 bytes, H - 4 bytes, L - 4 bytes
    if len(data) < 12:
        return False

    try:
        unpacked_data = struct.unpack(fields, data[:12])
    except struct.error:
        print("Error: Insufficient data length for ICMP header")
        return False

    icmp_type, code, checksum, identifier, sequence = unpacked_data
    payload = data[8:]  # rest of the packet is payload

    detected = False

    if icmp_type == 8 and code == 0 and identifier > 0 and sequence > 0:
        victim_ip = ipv4(icmp_packet(data)[5])  # Extracting victim IP from the tuple
        if victim_ip not in ip_address_set:
            ip_address_set.add(victim_ip)
            ip_count_dict[victim_ip] = 1  # Initialize count for the new victim IP
        else:
            ip_count_dict[victim_ip] += 1  # Increment count for existing victim IP

        if ip_count_dict[victim_ip] >= THRESHOULD:  # Check if the count exceeds the threshold
            detected = True

    return detected

def detect_icmp_time_exceeded_attack(log_file):
    """
    ICMP Time Exceeded Attack detection implementation.

    :param log_file: The log file containing network activity logs.
    :return: True if a Time Exceeded attack is detected, False otherwise.
    """
    ICMP_TIME_EXCEEDED_ATTACK_THRESHOLD = 10
    ICMP_TIME_EXCEEDED_ATTACK_WINDOW = 60

    icmp_packets = 0
    icmp_time_exceeded_attack_detected = False
    icmp_attack_window_start = None
    icmp_timestamps = set()  # Use a set to automatically remove duplicates

    ip_address_set = set()
    ip_count_dict = {}

    try:
        with open(log_file, 'r') as f:
            for line in f:
                log = line.strip().split(',')
                if len(log) >= 2 and log[1] == 'Time Exceeded':
                    icmp_packets += 1
                    current_time = datetime.datetime.strptime(log[0], '%Y-%m-%d %H:%M:%S')
                    if icmp_attack_window_start is None:
                        icmp_attack_window_start = current_time
                    elif (current_time - icmp_attack_window_start).total_seconds() < ICMP_TIME_EXCEEDED_ATTACK_WINDOW:
                        icmp_timestamps.add(current_time)
                        if len(icmp_timestamps) > ICMP_TIME_EXCEEDED_ATTACK_THRESHOLD:
                            # Ensure robust comparison of timestamps
                            if (datetime.datetime.now() - sorted(icmp_timestamps)[-ICMP_TIME_EXCEEDED_ATTACK_THRESHOLD]).total_seconds() < ICMP_TIME_EXCEEDED_ATTACK_WINDOW:
                                icmp_time_exceeded_attack_detected = True
                                break
                    else:
                        icmp_packets = 1
                        icmp_attack_window_start = current_time
                        icmp_timestamps = set([current_time])
                elif len(log) >= 2 and log[1] == 'Echo':
                    if ping_flood(log[2], ip_address_set, ip_count_dict):
                        print("Ping Flood attack detected!")
                        return True  # Exit early if a ping flood attack is detected
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"Error parsing log file '{log_file}': {e}")

    return icmp_time_exceeded_attack_detected

#DESTINATION UNREACHABLE Attack
def detect_icmp_destination_unreachable_attack(log_file):
    """
    ICMP Destination Unreachable Attack detection implementation.

    :param log_file: The log file containing network activity logs.
    :return: True if a Destination Unreachable attack is detected, False otherwise.
    """
    ICMP_DESTINATION_UNREACHABLE_ATTACK_THRESHOLD = 10
    ICMP_DESTINATION_UNREACHABLE_ATTACK_WINDOW = 60

    icmp_packets = 0
    icmp_destination_unreachable_attack_detected = False
    icmp_attack_window_start = None
    icmp_timestamps = set()  # Use a set to automatically remove duplicates

    try:
        with open(log_file, 'r') as f:
            for line in f:
                log = line.strip().split(',')
                if len(log) >= 2 and log[1] == 'Destination Unreachable':
                    icmp_packets += 1
                    current_time = datetime.datetime.strptime(log[0], '%Y-%m-%d %H:%M:%S')
                    if icmp_attack_window_start is None:
                        icmp_attack_window_start = current_time
                    elif (current_time - icmp_attack_window_start).total_seconds() < ICMP_DESTINATION_UNREACHABLE_ATTACK_WINDOW:
                        icmp_timestamps.add(current_time)
                        if len(icmp_timestamps) > ICMP_DESTINATION_UNREACHABLE_ATTACK_THRESHOLD:
                            if (datetime.datetime.now() - sorted(icmp_timestamps)[-ICMP_DESTINATION_UNREACHABLE_ATTACK_THRESHOLD]).total_seconds() < ICMP_DESTINATION_UNREACHABLE_ATTACK_WINDOW:
                                icmp_destination_unreachable_attack_detected = True
                                break
                    else:
                        icmp_packets = 1
                        icmp_attack_window_start = current_time
                        icmp_timestamps = set([current_time])
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
    except Exception as e:
        print(f"Error parsing log file '{log_file}': {e}")

    return icmp_destination_unreachable_attack_detected

def detect_icmp_redirection_attack(icmp_type, log_file):

    """
    ICMP Redirection Attack detection implementation.
    """
    detected = False
    if icmp_type == 5:
        detected = True    

    return detected
    
if __name__ == '__main__':
    main()
