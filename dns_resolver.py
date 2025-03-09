import socket
import struct
import random
import re

def validate_domain(domain):
    """验证域名格式"""
    pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None
def resolve_dns(domain, dns_server='8.8.8.8', timeout=5):
    query = build_query(domain)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(512)
    return parse_response(data)

def build_query(domain):
    transaction_id = random.randint(0, 65535)
    header = struct.pack('!HHHHHH', transaction_id, 0x0100, 1, 0, 0, 0)
    qname = b''.join(struct.pack('!B', len(part)) + part.encode()
                    for part in domain.split('.')) + b'\x00'
    question = qname + struct.pack('!HH', 1, 1)
    return header + question

def parse_response(data):
    if struct.unpack('!HHHHHH', data[:12])[3] == 0:
        return []
    offset = 12
    while data[offset] != 0:
        offset += data[offset] + 1
    offset += 5
    ips = []
    for _ in range(struct.unpack('!HHHHHH', data[:12])[3]):
        offset = parse_name(data, offset)[1]
        type_, _, _, data_len = struct.unpack('!HHIH', data[offset:offset+10])
        offset += 10
        if type_ == 1 and data_len == 4:
            ips.append('.'.join(map(str, struct.unpack('!4B', data[offset:offset+4]))))
        offset += data_len
    return ips

def parse_name(data, offset):
    name = []
    while True:
        length = data[offset]
        if (length & 0xC0) == 0xC0:
            ptr = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            part, _ = parse_name(data, ptr)
            name.extend(part)
            offset += 2
            break
        elif length == 0:
            offset += 1
            break
        else:
            offset += 1
            name.append(data[offset:offset+length].decode())
            offset += length
    return name, offset