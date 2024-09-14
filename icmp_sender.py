import socket
import sys

# Function to validate IP address
def validate_ip(ip):
    octets = ip.split('.')
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit():
            return False
        num = int(octet)
        if not 0 <= num <= 255:
            return False
        if octet != str(num):
            return False
    return True

# Function to calculate the checksum of the packet
def checksum(data):
    sum = 0
    length = len(data)
    i = 0
    while length > 1:
        sum += (data[i] << 8) + data[i + 1]
        i += 2
        length -= 2
    if length:
        sum += (data[i] << 8)
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += (sum >> 16)
    return ~sum & 0xFFFF

# Function to pack ICMP header manually
def pack_icmp_header(type, code, checksum, identifier, sequence_number):
    header = bytearray()
    header.append(type)  # Type
    header.append(code)  # Code
    header.extend(checksum.to_bytes(2, byteorder='big'))  # Checksum
    header.extend(identifier.to_bytes(2, byteorder='big'))  # Identifier
    header.extend(sequence_number.to_bytes(2, byteorder='big'))  # Sequence Number
    return header

# Function to create an ICMP packet
def create_icmp_packet(id, sequence):
    type = 8  # Echo Request
    code = 0
    checksum_value = 0
    identifier = id
    sequence_number = sequence

    icmp_header = pack_icmp_header(type, code, checksum_value, identifier, sequence_number)
    data = b'hello'
    packet = icmp_header + data

    checksum_value = checksum(packet)
    icmp_header = pack_icmp_header(type, code, checksum_value, identifier, sequence_number)
    packet = icmp_header + data

    return packet

# Function to create an IP header manually
def create_ip_header(source_ip, dest_ip, payload_length):
    version = 4
    ihl = 5
    tos = 0
    tot_len = 20 + payload_length
    id = 54321
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_ICMP
    check = 0
    source = socket.inet_aton(source_ip)
    dest = socket.inet_aton(dest_ip)

    # Manual IP header creation
    ip_header = bytearray()
    ip_header.append((version << 4) + ihl)  # Version and IHL
    ip_header.append(tos)  # Type of Service
    ip_header.extend(tot_len.to_bytes(2, byteorder='big'))  # Total Length
    ip_header.extend(id.to_bytes(2, byteorder='big'))  # Identification
    ip_header.extend(frag_off.to_bytes(2, byteorder='big'))  # Fragment Offset
    ip_header.append(ttl)  # Time to Live
    ip_header.append(protocol)  # Protocol
    ip_header.extend(check.to_bytes(2, byteorder='big'))  # Header Checksum (initially 0)
    ip_header.extend(source)  # Source IP
    ip_header.extend(dest)  # Destination IP

    return ip_header

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <source_ip> <destination_ip>")
        sys.exit(1)

    source_ip = sys.argv[1]
    destination_ip = sys.argv[2]

    if not validate_ip(source_ip) or not validate_ip(destination_ip):
        print("Invalid IP address.")
        sys.exit(1)

    print(f"Source IP: {source_ip}")
    print(f"Destination IP: {destination_ip}")

    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        print("Permission denied: Raw sockets require root privileges.")
        sys.exit(1)

    # Create ICMP packet
    icmp_payload = create_icmp_packet(id=1, sequence=1)
    ip_header = create_ip_header(source_ip, destination_ip, len(icmp_payload))
    packet = ip_header + icmp_payload

    # Send the packet
    try:
        raw_socket.sendto(packet, (destination_ip, 0))
        print(f"ICMP packet sent to {destination_ip}")
    except Exception as e:
        print(f"Failed to send packet: {e}")
    raw_socket.close()

if __name__ == "__main__":
    main()
