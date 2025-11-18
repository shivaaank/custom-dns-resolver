#!/usr/bin/env python3
"""
Recursive DNS resolver with ad/tracker blocking.
Uses StevenBlack's hosts list to block ads automatically.
Caches resolved DNS records to reduce upstream queries.
"""

import socket
import struct
import random
import time
import requests
from concurrent.futures import ThreadPoolExecutor

ROOT_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12",  # Original root servers
    "8.8.8.8", "8.8.4.4",  # Google DNS
    "1.1.1.1", "1.0.0.1"  # Cloudflare DNS
]

SOCKET_TIMEOUT = 2.0  # seconds for upstream queries
BLOCKLIST_PATH = "hosts.blocklist"  # Path to local blocklist file

# ---------------------------
# Load blocklist from local file
# ---------------------------
def load_blocklist():
    try:
        with open(BLOCKLIST_PATH, 'r') as f:
            lines = f.readlines()
        blocked = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                blocked.add(parts[1].lower())
        print(f"[+] Loaded {len(blocked)} blocked domains from local blocklist")
        return blocked
    except Exception as e:
        print(f"[!] Could not load blocklist: {e}")
        return set()

ADBLOCK_LIST = load_blocklist()

# ---------------------------
# DNS Cache
# ---------------------------
dns_cache = {}
failed_cache = {}

def get_cached_ip(domain: str):
    """Get the cached IP address for a domain, if available."""
    if domain.lower() in failed_cache:
        # Check if the domain is still in the failed cache and if enough time has passed to retry
        failure_time = failed_cache[domain.lower()]
        if time.time() - failure_time < 3600:  # 1 hour timeout (can adjust)
            return None  # Don't retry within the timeout period
        else:
            del failed_cache[domain.lower()]  # Allow retry after timeout
    return dns_cache.get(domain.lower())

def set_cached_ip(domain: str, ip: str):
    """Store the resolved IP address in the cache."""
    if ip == "0.0.0.0":
        failed_cache[domain.lower()] = time.time()  # Store the time of failure
    else:
        dns_cache[domain.lower()] = ip

# ---------------------------
# Wire-format helpers
# ---------------------------

def encode_name(name: str) -> bytes:
    if name == "":
        return b"\x00"
    parts = name.split(".")
    out = b""
    for p in parts:
        out += bytes([len(p)]) + p.encode("utf-8")
    out += b"\x00"
    return out

def decode_name(data: bytes, offset: int):
    labels = []
    orig_offset = offset
    jumped = False
    while True:
        if offset >= len(data):
            return ("", offset + 1)
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return ("", offset + 2)
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8"))
        offset += length
    return (".".join(labels), (orig_offset if jumped else offset))


# ---------------------------
# Build DNS query to upstream
# ---------------------------
def build_query(domain: str, qtype: int = 1) -> (int, bytes):
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = encode_name(domain) + struct.pack(">HH", qtype, 1)
    return tid, header + question

def parse_response(data: bytes):
    if len(data) < 12:
        return [], [], []
    qdcount, ancount, nscount, arcount = struct.unpack(">xxxxHHHH", data[:12])
    offset = 12
    for _ in range(qdcount):
        _, offset = decode_name(data, offset)
        offset += 4
    def read_rrs(count):
        nonlocal offset
        out = []
        for _ in range(count):
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                return out
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10
            rdata = data[offset:offset+rdlen]
            offset += rdlen
            out.append((rtype, rdata))
        return out
    answers = read_rrs(ancount)
    ns = read_rrs(nscount)
    add = read_rrs(arcount)
    return answers, ns, add

def send_upstream_query(server_ip: str, packet: bytes) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(SOCKET_TIMEOUT)
    try:
        s.sendto(packet, (server_ip, 53))
        resp, _ = s.recvfrom(4096)
        return resp
    finally:
        s.close()

def find_a_record(domain: str) -> str:
    # Check cache first
    cached_ip = get_cached_ip(domain)
    if cached_ip:
        if cached_ip == "0.0.0.0":  # If the cache shows 0.0.0.0, don't resolve again, but log and return
            print(f"[CACHE] {domain} failed previously, not resolving.")
            return "0.0.0.0"  # Can return NXDOMAIN or a more informative error here
        else:
            print(f"[CACHE] {domain} found in cache: {cached_ip}")
            return cached_ip

    print(f"[DEBUG] Resolving A record for {domain}...")
    for attempt in range(5):  # Try 5 times with random servers
        server = random.choice(ROOT_SERVERS)
        try:
            tid, q = build_query(domain, qtype=1)
            print(f"[QUERY] Sending request to {server} for {domain}")
            resp = send_upstream_query(server, q)
            print(f"[DEBUG] Response received for {domain} from {server}")
            answers, ns, add = parse_response(resp)
            if answers:
                for rtype, rdata in answers:
                    if rtype == 1 and len(rdata) == 4:
                        ip = socket.inet_ntoa(rdata)
                        set_cached_ip(domain, ip)  # Store in cache
                        print(f"[ANSWER] {domain} -> {ip}")
                        return ip
        except Exception as e:
            print(f"[ERROR] Error querying {server}: {e}")
            continue

    # Fallback if resolution failed after retries
    print(f"[!] Could not resolve A record for {domain}, returning 0.0.0.0")
    set_cached_ip(domain, "0.0.0.0")  # Cache the failure
    return "0.0.0.0"  # Return a fallback IP for blocked domains



def build_response(request: bytes, ip: str) -> bytes:
    if len(request) < 12:
        return b""
    tid = request[0:2]

    rd_flag = request[2:3]

    rd_bit = ord(rd_flag) & 0x01
    flags = (0x8000 | (rd_bit << 8) | 0x0080)

    flags_bytes = struct.pack(">H", flags)
    qdcount = request[4:6]
    ancount = struct.pack(">H", 1)
    nscount = struct.pack(">H", 0)
    arcount = struct.pack(">H", 0)
    header = tid + flags_bytes + qdcount + ancount + nscount + arcount

    offset = 12
    while offset < len(request) and request[offset] != 0:
        offset += request[offset] + 1
    offset += 1 + 4
    question = request[12:offset]

    name_ptr = b"\xC0\x0C"
    type_a = struct.pack(">H", 1)
    class_in = struct.pack(">H", 1)
    ttl = struct.pack(">I", 60)
    rdlength = struct.pack(">H", 4)
    rdata = socket.inet_aton(ip)
    answer = name_ptr + type_a + class_in + ttl + rdlength + rdata
    return header + question + answer


def serve(bind_addr="0.0.0.0", port=53):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_addr, port))
    print(f"[+] DNS UDP server listening on {bind_addr}:{port}")
    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except Exception:
                continue

            try:
                qname, _ = decode_name(data, 12)
                qname_lower = qname.lower()
                print(f"[QUERY] Received query for {qname_lower} from {addr[0]}")

                # Check if domain is blocked
                blocked = False
                parts = qname_lower.split(".")
                for i in range(len(parts)):
                    subdomain = ".".join(parts[i:])
                    if subdomain in ADBLOCK_LIST:
                        blocked = True
                        break

                if blocked:
                    # Send NXDOMAIN response for blocked domains
                    print(f"[BLOCKED] {qname_lower} is blocked, returning NXDOMAIN")
                    flags = struct.pack(">H", 0x8183)  # QR=1, RCODE=3 NXDOMAIN
                    response = build_response(data, "0.0.0.0")
                else:
                    # Resolve normally
                    ip = find_a_record(qname_lower)
                    response = build_response(data, ip)

                sock.sendto(response, addr)
            except Exception as e:
                print(f"[ERROR] Error processing request: {e}")
                continue
    except KeyboardInterrupt:
        print("[!] Shutting down server.")
    finally:
        sock.close()


if __name__ == "__main__":
    serve()
