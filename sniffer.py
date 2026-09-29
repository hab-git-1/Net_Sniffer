import socket
import struct
import textwrap

def main():
    try:
        # AF_PACKET is Linux-specific for raw network interfaces
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("[!] Error: Permission denied. Please run this script as root/administrator.")
        return
    except AttributeError:
        # Fallback for Windows environments
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind(("0.0.0.0", 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print("[*] Basic Network Sniffer Started... Press Ctrl+C to stop.\n")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            
            # Layer 2 Ethernet header is 14 bytes long
            eth_header = raw_data[:14]
            eth_protocol = struct.unpack('! H', eth_header[12:14])[0]
            
            # 0x0800 indicates IPv4
            if eth_protocol == 0x0800:
                ip_data = raw_data[14:]
                version, header_length, ttl, proto, src, target, payload = ipv4_packet(ip_data)
                
                print("\n" + "=" * 50)
                print(f"[+] IPv4 Packet:")
                print(f"    |- Version: {version}, Header Length: {header_length} bytes, TTL: {ttl}")
                print(f"    |- Protocol: {proto_name(proto)} ({proto})")
                print(f"    |- Source IP: {src}")
                print(f"    |- Destination IP: {target}")

                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, icmp_data = icmp_packet(payload)
                    print(f"    [+] ICMP Packet:")
                    print(f"        |- Type: {icmp_type}, Code: {code}, Checksum: {checksum}")
                    print_payload(icmp_data)

                # TCP
                elif proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flags, tcp_data = tcp_segment(payload)
                    print(f"    [+] TCP Segment:")
                    print(f"        |- Source Port: {src_port}, Destination Port: {dest_port}")
                    print(f"        |- Sequence: {sequence}, Acknowledgment: {acknowledgment}")
                    print(f"        |- Flags: URGE={flags['URG']}, ACK={flags['ACK']}, PSH={flags['PSH']}, RST={flags['RST']}, SYN={flags['SYN']}, FIN={flags['FIN']}")
                    print_payload(tcp_data)

                # UDP
                elif proto == 17:
                    src_port, dest_port, length, udp_data = udp_segment(payload)
                    print(f"    [+] UDP Segment:")
                    print(f"        |- Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")
                    print_payload(udp_data)

    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user.")


# --- HELPER FUNCTIONS & DECODERS ---

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ip(src), format_ip(target), data[header_length:]

def format_ip(addr):
    return '.'.join(map(str, addr))

def proto_name(proto_num):
    protocols = {1: "ICMP", 6: "TCP", 17: "UDP"}
    return protocols.get(proto_num, "Other")

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1
    }
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

def print_payload(data, format_width=80):
    if not data:
        return
    print("    [+] Payload:")
    try:
        decoded_data = data.decode('utf-8', errors='replace')
        lines = textwrap.wrap(decoded_data, width=format_width)
        for line in lines:
            print(f"        {line}")
    except Exception:
        print(f"        {data}")


# --- ENTRY POINT ---
if __name__ == '__main__':
    main()