import socket
import sys

# Validate an IP address
def validate_ip(ip):
    octets = ip.split('.')
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit() or not 0 <= int(octet) <= 255:
            return False
    return True

# Calculate the checksum of the packet
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

# Pack ICMP header manually
def pack_icmp_header(type, code, checksum, identifier, sequence_number):
    header = bytearray()
    header.append(type)
    header.append(code)
    header.extend(checksum.to_bytes(2, 'big'))
    header.extend(identifier.to_bytes(2, 'big'))
    header.extend(sequence_number.to_bytes(2, 'big'))
    return header

# Create ICMP packet
def create_icmp_packet(id, sequence):
    type = 8  # Echo Request
    code = 0
    checksum_value = 0
    icmp_header = pack_icmp_header(type, code, checksum_value, id, sequence)
    data = b'hello'
    packet = icmp_header + data
    checksum_value = checksum(packet)
    icmp_header = pack_icmp_header(type, code, checksum_value, id, sequence)
    return icmp_header + data

# Create IP header manually
def create_ip_header(source_ip, dest_ip, payload_length):
    version = 4
    ihl = 5
    tos = 0
    tot_len = 20 + payload_length
    id = 54321
    frag_off = 0
    ttl = 64
    protocol = socket.IPPROTO_ICMP
    source = socket.inet_aton(source_ip)
    dest = socket.inet_aton(dest_ip)

    ip_header = bytearray()
    ip_header.append((version << 4) + ihl)
    ip_header.append(tos)
    ip_header.extend(tot_len.to_bytes(2, 'big'))
    ip_header.extend(id.to_bytes(2, 'big'))
    ip_header.extend(frag_off.to_bytes(2, 'big'))
    ip_header.append(ttl)
    ip_header.append(protocol)
    ip_header.extend(b'\x00\x00')  # Initial checksum (will be calculated later)
    ip_header.extend(source)
    ip_header.extend(dest)

    check = checksum(ip_header)
    ip_header[10:12] = check.to_bytes(2, 'big')
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

    # Create and send ICMP packet
    icmp_payload = create_icmp_packet(id=1, sequence=1)
    ip_header = create_ip_header(source_ip, destination_ip, len(icmp_payload))
    packet = ip_header + icmp_payload

    try:
        raw_socket.sendto(packet, (destination_ip, 0))
        print(f"ICMP packet sent to {destination_ip}")
    except Exception as e:
        print(f"Failed to send packet: {e}")
    finally:
        raw_socket.close()

if __name__ == "__main__":
    main()
