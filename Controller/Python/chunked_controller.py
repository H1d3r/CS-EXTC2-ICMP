from scapy.all import sniff, send, IP, ICMP, Raw, RandShort
import subprocess
import time
import struct 

ICMP_TAG = b"RQ47"
CHUNK_HEADER_SIZE = 12  # 4 tag + 4 chunk_index + 4 total_chunks
sessions = {}

class ICMPSession:
    def __init__(self, session_id, total_chunks, src_ip):
        self.session_id = session_id
        self.src_ip = src_ip
        self.total_chunks = total_chunks
        self.chunks = {}
        self.created = time.time()

    def add_chunk(self, chunk_index, data):
        self.chunks[chunk_index] = data

    def is_complete(self):
        return len(self.chunks) == self.total_chunks

    def get_data(self):
        return b''.join(self.chunks[i] for i in sorted(self.chunks))

def disable_os_icmp():
    print("=" * 24)
    print("[+] Disabling OS ICMP Echo Responses...")
    result = subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1"], capture_output=True, text=True)
    print("STDOUT:", result.stdout.strip())
    print("STDERR:", result.stderr.strip())
    print("Exit Code:", result.returncode)
    if "net.ipv4.icmp_echo_ignore_all = 1" in result.stdout:
        print("[+] Success: ICMP Echo handling is now script-controlled.")
    print("=" * 24)

def cleanup_sessions(timeout=60):
    now = time.time()
    for key in list(sessions.keys()):
        if now - sessions[key].created > timeout:
            print(f"[-] Expired old session from {key[0]}")
            del sessions[key]

def handle_tagged_chunk(packet):
    try:
        if not packet.haslayer(Raw):
            return

        payload = packet[Raw].load
        if not payload.startswith(ICMP_TAG) or len(payload) < CHUNK_HEADER_SIZE:
            return

        ip_src = packet[IP].src
        icmp_id = packet[ICMP].id
        icmp_seq = packet[ICMP].seq

        chunk_index = struct.unpack(">I", payload[4:8])[0]
        total_chunks = struct.unpack(">I", payload[8:12])[0]
        data = payload[12:]

        key = (ip_src, icmp_id)
        if key not in sessions:
            sessions[key] = ICMPSession(icmp_id, total_chunks, ip_src)

        session = sessions[key]
        session.add_chunk(chunk_index, data)
        print(f"[+] Chunk {chunk_index + 1}/{total_chunks} received from {ip_src} (seq {icmp_seq})")

        if session.is_complete():
            full_data = session.get_data()
            print(f"[✓] Full message reassembled from {ip_src}")
            print(f"    Payload: {full_data.decode(errors='replace')}")
            del sessions[key]

        reply_payload = ICMP_TAG + b"PLACEHOLDER_TRANSMISSION_HAS_FINISHED"
       # reply = IP(dst=ip_src, src=packet[IP].dst) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=reply_payload)
        reply = IP(
            dst=ip_src,
            src=packet[IP].dst,
            id=RandShort(),          # Make sure IP ID isn't default
            flags=0,
            ttl=64,
        ) / ICMP(
            type=0,
            id=icmp_id,
            seq=icmp_seq
        ) / Raw(load=reply_payload)
        send(reply, verbose=False)

    except Exception as e:
        print(f"[!] Error handling chunk: {e}")

def handle_icmp(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        if packet.haslayer(Raw) and packet[Raw].load.startswith(ICMP_TAG):
            handle_tagged_chunk(packet)
        else:
            try:
                ip_src = packet[IP].src
                icmp_id = packet[ICMP].id
                icmp_seq = packet[ICMP].seq
                icmp_data = packet[Raw].load if Raw in packet else b''

                reply = IP(dst=ip_src, src=packet[IP].dst) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=icmp_data)
                send(reply, verbose=False)
                print(f"[+] Standard echo reply sent to {ip_src}")
            except Exception as e:
                print(f"[!] Error replying to standard ping: {e}")

disable_os_icmp()
print("[+] ICMP Chunk Receiver is running...")
sniff(filter="icmp", prn=handle_icmp, store=False)
