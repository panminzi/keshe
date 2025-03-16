import socket
import struct
import random
import re
import time
import binascii
from venv import logger

def validate_domain(domain):
    """验证域名格式"""
    pattern = r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None


def resolve_dns(domain, logger=None):
    """带过程记录的解析"""
    try:
        if logger: logger.add_step("开始解析", True)

        # 构建查询报文
        if logger: logger.add_step("构建查询报文", True)
        query = build_query(domain)

        # 发送请求
        if logger: logger.add_step("发送请求", True, "使用UDP协议")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            sock.sendto(query, ('8.8.8.8', 53))#谷歌公共DNS地址，53为端口号、udp协议

    # 等待响应
            if logger: logger.add_step("等待响应", True, "超时：5秒")
            data, _ = sock.recvfrom(512)#从 UDP 套接字中接收数据包，最多接收 512 字节 的数据，返回数据，忽略地址
        # 解析响应
        if logger: logger.add_step("解析响应", True)
        ips = parse_response(data)

        if logger: logger.add_step("完成解析", True,
                                   f"找到 {len(ips)} 个IP" if ips else "无结果")
        return ips

    except Exception as e:
        if logger: logger.add_step("解析失败", False, str(e))
        raise
'''
def resolve_dns(domain, dns_server='8.8.8.8', timeout=5):
    query = build_query(domain)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (dns_server, 53))
        data, _ = sock.recvfrom(512)
    return parse_response(data)
    '''


def build_query(domain, logger=None):
    """构造DNS查询报文"""
    # 构造 DNS 报文头部
    header = struct.pack('!HHHHHH',
                         random.randint(0, 65535),  # 事务ID，用于匹配请求与响应，确保查询的唯一性
                         0x0100,  # 标志，（标准查询 + 递归查询）
                         1, 0, 0, 0#问题数=1，其余字段均为0
                         )
     #构造域名编码
    qname = b''
    for part in domain.encode().split(b'.'):
        qname += struct.pack('!B', len(part)) + part
    qname += b'\x00'
   #构造问题部分
    question = qname + struct.pack('!HH', 1, 1)#第一个1表示A 记录（IPv4 地址），第二个表示互联网类
    packet = header + question# 拼接完整报文
    # 添加报文记录
    hex_packet = binascii.hexlify(packet).decode('utf-8')
    formatted_packet = ' '.join([hex_packet[i:i+32] for i in range(0, len(hex_packet), 32)])#32 字符的十六进制字符串就空格
    if logger:
        logger.add_step("构造查询报文", True, f"报文：{formatted_packet}")
        print("构造报文"+f"{formatted_packet}")
    return packet

'''
    if logger:
        hex_packet = binascii.hexlify(packet).decode()
        logger.add_step(
            "构造查询报文",
            True,
            f"十六进制报文:\n{format_hex(hex_packet)}"
        )
    return packet
    '''
'''
def build_query(domain):
    transaction_id = random.randint(0, 65535)
    header = struct.pack('!HHHHHH', transaction_id, 0x0100, 1, 0, 0, 0)
    qname = b''.join(struct.pack('!B', len(part)) + part.encode()
                    for part in domain.split('.')) + b'\x00'
    question = qname + struct.pack('!HH', 1, 1)
    packet= header + question
    if logger:
        hex_packet = binascii.hexlify(packet).decode()
        logger.add_step(
            "构造查询报文",
            True,
            f"十六进制报文:\n{format_hex(hex_packet)}"
        )
    return packet
'''



def parse_response(data, logger=None):
    """带解析记录的响应处理"""
    steps = []

    # 解析头部
    steps.append("解析响应头")
    tid, flags, qdcount, ancount, _, _ = struct.unpack('!HHHHHH', data[:12])

    if logger:
        logger.add_step("解析响应头", True,
                        f"事务ID: {tid}  "
                        f"问题数: {qdcount  }"
                        f"回答数: {ancount}"
                        )

    # 跳过问题部分
    offset = 12
    while data[offset] != 0:
        offset += data[offset] + 1
    offset += 5

    # 解析回答
    ips = []
    for i in range(ancount):
        # 解析域名指针
        steps.append(f"解析第{i + 1}个回答")
        name, offset = parse_name(data, offset)

        # 解析资源记录
        type_, class_, ttl, data_len = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10


        if type_ == 1 and class_ == 1 and data_len == 4:
            ip = struct.unpack('!4B', data[offset:offset + 4])
            ips.append('.'.join(map(str, ip)))
            if logger:
                logger.add_step("提取IP地址", True,
                    f"类型: A记录  "
                    f"TTL: {ttl}秒 "
                    f"IP: {ips[-1]}"
                )
        offset += data_len
    return ips
'''
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
'''
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