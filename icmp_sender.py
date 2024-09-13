import socket
import sys


# Function to validate IP address
def validate_ip(ip):
    # Split the IP address into octets
    octets = ip.split('.')

    # Check if there are exactly four octets
    if len(octets) != 4:
        return False

    for octet in octets:
        # Check if the octet is a valid integer
        if not octet.isdigit():
            return False

        # Convert the octet to an integer
        num = int(octet)

        # Check if the integer is within the valid range
        if not 0 <= num <= 255:
            return False

        # Ensure that no octet has leading zeros unless it's just '0'
        if octet != str(num):
            return False

    return True


# Function to calculate the checksum of the ICMP packet
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


# Function to pack data into binary format manually
def pack_icmp_header(type, code, checksum, identifier, sequence_number):
    header = bytearray()

    # Type and Code
    header.append(type)
    header.append(code)

    # Checksum (2 bytes)
    header.extend(checksum.to_bytes(2, byteorder='big'))

    # Identifier (2 bytes)
    header.extend(identifier.to_bytes(2, byteorder='big'))

    # Sequence Number (2 bytes)
    header.extend(sequence_number.to_bytes(2, byteorder='big'))

    return header


# Function to create an ICMP echo request packet
def create_icmp_packet(id, sequence):
    type = 8
    code = 0
    checksum_value = 0
    identifier = id
    sequence_number = sequence

    # Create header with initial checksum value
    icmp_header = pack_icmp_header(type, code, checksum_value, identifier, sequence_number)
    data = b'hello'  # Example payload data
    packet = icmp_header + data

    # Compute checksum
    checksum_value = checksum(packet)
    icmp_header = pack_icmp_header(type, code, checksum_value, identifier, sequence_number)
    packet = icmp_header + data

    return packet


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

    # Create a raw socket
    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Permission denied: Raw sockets require root privileges.")
        sys.exit(1)

    # Create and send ICMP packet
    icmp_packet = create_icmp_packet(id=1, sequence=1)

    try:
        raw_socket.sendto(icmp_packet, (destination_ip, 0))
        print(f"ICMP packet sent to {destination_ip}")
    except Exception as e:
        print(f"Failed to send packet: {e}")
    raw_socket.close()


if __name__ == "__main__":
    main()
