from scapy.all import sniff, send, IP, ICMP, Raw
import time
import subprocess
'''
ICMP POC server to capture ICMP messages

Also - for whatever reason, localhost / ip of machine the server is running on (ex if ip = 10.0.0.2 and it sends it to itself) it doesn't show up


'''

ICMP_TAG = "RQ47"

def handle_all_packet(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        print(f"[+] ICMP from {packet[IP].src}: Type={packet[ICMP].type}, Code={packet[ICMP].code}")

        # vars for some data that is needed
        ip_src = packet[IP].src if packet[IP].src else None
        icmp_type = packet[ICMP].type if packet[ICMP].type else None
        icmp_code = packet[ICMP].code if packet[ICMP].code else None
        icmp_id = packet[ICMP].id if packet[ICMP].id else None
        icmp_seq = packet[ICMP].seq if packet[ICMP].seq else None
        icmp_data = packet["Raw"].load if packet["Raw"].load else None


        # only put needed fields here. Could just return the packet, but this is simpler
        icmp_dict = {
            "icmp_id":icmp_id,
            "icmp_seq":icmp_seq,
            "icmp_code":icmp_code,
            "icmp_type":icmp_type,
            "icmp_src":ip_src,
            "icmp_data": icmp_data
        }

        response_payload = b"SomePayload"
        reply = IP(dst=ip_src, src="127.0.0.9") / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=response_payload)
        send(reply, verbose=False)
        print(f"[+] Replied to {ip_src}, {reply}")

        #print(icmp_dict)
        return icmp_dict

        #packet.show() # print entire packet contents
        # print("Raw payload:")
        # if packet.haslayer("Raw"):
        #     print(packet["Raw"].load)
        # else:
        #     print("No raw data.\n")

# def banner(message):
#     print("=" * 24)
#     print(f"{message}")
#     print("=" * 24)

def disable_os_icmp():
    '''
    Disables OS echo reply response
    
    '''
    print("=" * 24)

    print("[+] Attempting to disable OS ICMP Echo Responses")
    result = subprocess.run(["sudo", "sysctl", "-w", "net.ipv4.icmp_echo_ignore_all=1"], capture_output=True, text=True)

    print("STDOUT:", result.stdout)
    print("STDERR:", result.stderr)
    print("Exit Code:", result.returncode)
    if "net.ipv4.icmp_echo_ignore_all = 1" in result.stdout:
        print("[+] Success. ICMP Echo handling has been replaced by this script.")
    print("=" * 24)

def handle_icmp(packet):
    '''
    A replacement layer for echo requests. Handles special tagged packets with one set of rules, handles standard ICMP with another, to keep ICMP working
    
    '''
    if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet["Raw"].load.startswith(ICMP_TAG.encode()):
        try:
            print(f"[+] Tagged ICMP from {packet[IP].src}: Type={packet[ICMP].type}, Code={packet[ICMP].code}")

            # vars for some data that is needed
            ip_src = packet[IP].src if packet[IP].src else None
            icmp_type = packet[ICMP].type if packet[ICMP].type else None
            icmp_code = packet[ICMP].code if packet[ICMP].code else None
            icmp_id = packet[ICMP].id if packet[ICMP].id else None
            icmp_seq = packet[ICMP].seq if packet[ICMP].seq else None
            icmp_data = packet["Raw"].load if packet["Raw"].load else None


            # only put needed fields here. Could just return the packet, but this is simpler
            icmp_dict = {
                "icmp_id":icmp_id,
                "icmp_seq":icmp_seq,
                "icmp_code":icmp_code,
                "icmp_type":icmp_type,
                "icmp_src":ip_src,
                "icmp_data": icmp_data
            }

            # on message, send a payload back
            # move to own func
            #time.sleep(3) # test delay - WROKS! :)
            response_payload = ICMP_TAG.encode() # add in tag
            response_payload += b"SomePayload" # add in payload
            # The src must be the original dest IP, otherwise it will get blocked
            reply = IP(dst=ip_src, src=packet[IP].dst) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=response_payload)
            send(reply, verbose=False)
            print(f"[+] Replied to {ip_src}, {reply}")

            #print(icmp_dict)
            return icmp_dict

        except Exception as e:
            print(f"[!] Error responding to {ICMP_TAG} Echo Request: {e}")

    # normal ping response
    elif packet.haslayer(ICMP) and packet[ICMP].type == 8:
        try:
            print(f"[+] Untagged ICMP from {packet[IP].src}: Type={packet[ICMP].type}, Code={packet[ICMP].code}")

            # vars for some data that is needed
            ip_src = packet[IP].src if packet[IP].src else None
            icmp_type = packet[ICMP].type if packet[ICMP].type else None
            icmp_code = packet[ICMP].code if packet[ICMP].code else None
            icmp_id = packet[ICMP].id if packet[ICMP].id else None
            icmp_seq = packet[ICMP].seq if packet[ICMP].seq else None
            icmp_data = packet["Raw"].load if packet["Raw"].load else None

            # Mirror back original packet as ICMP is supposed to.
            # The src must be the original dest IP, otherwise it will get blocked
            reply = IP(dst=ip_src, src=packet[IP].dst) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=icmp_data)
            send(reply, verbose=False)
            print(f"[+] Replied to {ip_src}, {reply}")
        except Exception as e:
            print(f"[!] Error responding to standard Echo Request: {e}")
disable_os_icmp()
print("[+] Sniffing ICMP...")
# store=false keeps packets out of memory for better perf
sniff(filter="icmp", prn=handle_icmp, store=False)
