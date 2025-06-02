from scapy.all import sniff, IP, ICMP

'''
ICMP POC server to capture ICMP messages

Also - for whatever reason, localhost / ip of machine the server is running on (ex if ip = 10.0.0.2 and it sends it to itself) it doesn't show up


'''

def handle_packet(packet):
    if packet.haslayer(ICMP):
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

        #print(icmp_dict)
        return icmp_dict

        #packet.show() # print entire packet contents
        # print("Raw payload:")
        # if packet.haslayer("Raw"):
        #     print(packet["Raw"].load)
        # else:
        #     print("No raw data.\n")


print("[+] Sniffing ICMP...")
sniff(filter="icmp", prn=handle_packet, store=False)
