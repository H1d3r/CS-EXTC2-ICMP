# ICMP_POC

#### Todo:

 - [X] POC bridge
    - [ ] Chunk Handling (ex, max msg size of 32 bytes, how to handle when bigger.)
        > create a new file called poc_chunked_controller for this.
        Controller side, maybe create a class that holds each communiciation + gets chunks, if seen before, access class, if not, new class?

 - [ ] Update readme to have docs/easy to read "how this works"
 - [ ] CS Integration:
    - [ ] Controller
    - [ ] Client:
        Pull & execute payloads


Bugs:
 - Not spawning beacon - no idea why - HOWEVER, if there is a smb beacon already running, it will connect to it if the pipe name is right
    Going to proceed with this, and worry about the shellcode later

    New issue: decrypt of metadata failed - so the data is not getting to the Extc2 correctly.
    Has to be something wrong on my end, as the provided example works flawlessly.

Problem: MSVC SUCKS BALLS. use `i686-w64-mingw32-gcc file.c -o example.exe -lws2_32` instead

IT WORKS! problem was extra \0x00 data on the end of the icmp data.

Currently, commands do not get passed to beacons now. yay. Might be another data thing

---
# ICMP C2 Protocol Overview

This document provides a high‐level description of how our ICMP-based command-and-control (C2) channel works. It explains the core handshake (Type 8 → Type 0) and how larger payloads are fragmented and reassembled.

---

## Key Concepts

- **ICMP Echo Request (Type 8)**: Used by the client (“agent”) to signal the server (“controller”) and request data.
- **ICMP Echo Reply (Type 0)**: Used by the controller to embed and send replies (including large payloads) back to the client.
- **TAG (4 bytes)**: A fixed 4-byte marker (e.g. `RQ47`) prepended to every ICMP payload, so that unrelated OS pings or network noise are ignored.
- **Chunking**: When the controller needs to send more data than fits in one ICMP packet (500 bytes), it splits the payload into multiple fragments. Each fragment still carries the same 4-byte tag.

---
# Setup:

1. Install dependencies:

```
sudo apt install libpcap0.8-dev
```

```
pip install -r Controller/Python/requirements.txt
```


2. Start an External C2 beacon in CS


3. run `python3 Controller/Python/controller.py`

---
## Overall Flow

1. **Client: “Seq 0” Size Request**  
   - The client opens a raw ICMP socket.  
   - It builds a small ICMP Echo Request (Type 8) whose payload is:  
     ```
     [TAG (4 bytes)] [4-byte big-endian integer: total_bytes_expected]
     ```  
   - The client sends this as **sequence 0**.  
   - Purpose: inform the controller how many bytes of data it plans to receive.

2. **Controller: Immediate “Seq 0” Reply (Size Confirmation)**  
   - The controller’s sniffer sees an ICMP packet where:  
     - Type == 8 (Echo Request)  
     - Payload starts with `TAG`  
     - Sequence == 0  
   - It extracts the 4-byte length, allocates a receive buffer of that size, and immediately responds with an ICMP Echo Reply (Type 0), also marked as **sequence 0**. Its payload is:  
     ```
     [TAG (4 bytes)] [4-byte big-endian integer: total_bytes_to_send]
     ```  
   - This confirms to the client that the server is ready to send exactly that many bytes.

3. **Controller: Sending Data Fragments (Seq 1..N)**  
   - If the data to send exceeds the single-packet limit (≈500 bytes total), the controller splits it into fragments of up to (500 − 4) = 496 bytes each.  
   - For each fragment **i** (starting at 1), the controller sends an ICMP Echo Reply (Type 0) with:  
     ```
     Sequence = i  
     Payload = [TAG][next 496 bytes of data]
     ```  
   - If the payload fits in one chunk, only “seq 1” is used. Otherwise, multiple replies arrive in sequence.

4. **Client: Reassembly Loop**  
   - After sending “seq 0” and waiting, the client’s raw socket filters incoming packets, accepting only:  
     - ICMP packets of Type 0 (Echo Reply)  
     - Matching its own process ID  
     - Payload beginning with `TAG`  
   - When **seq 0** arrives, the client reads the 4-byte length, allocates a buffer, and computes how many fragments it expects:  
     ```
     total_chunks = ceil(total_size / 496)
     ```  
   - For each subsequent reply **seq = 1..total_chunks**, the client copies the data portion (i.e., bytes after the TAG) into the right offset in the buffer. Once all fragments are received, the full payload is ready for execution or further processing.

5. **Beaconing & TeamServer Forwarding (Seq > 0)**  
   - After the initial C2 payload, the client may send extra frames (e.g., “beacon” or “task” data). Each of these is sent as an ICMP Echo Request (Type 8) with:  
     ```
     Sequence = X (> 0)  
     Payload = [TAG][user_data…]
     ```  
   - The controller, upon spotting `seq > 0`, strips `TAG` and forwards the remaining bytes to the TeamServer over a TCP socket.  
   - Any response from the TeamServer is sent back in a single ICMP Echo Reply (Type 0) with:  
     ```
     Sequence = X  
     Payload = [TAG][TeamServer_response]
     ```  
   - This ensures a 1:1 mapping of in-flight beacon frames to replies, using the same sequence number to correlate.

---

## Packet Structure Summary

- **Client → Controller (Seq 0)**  
  ```
  IP Header (20 bytes)
  └─ ICMP Header (8 bytes): Type=8, Code=0, ID=<PID>, Seq=0
     └─ Payload (500 bytes total): [“RQ47”][4-byte total_size][padding…]
  ```

- **Controller → Client (Seq 0 Reply)**  
  ```
  IP Header (20 bytes)
  └─ ICMP Header (8 bytes): Type=0, Code=0, ID=<PID>, Seq=0
     └─ Payload (500 bytes total): [“RQ47”][4-byte total_size][padding…]
  ```

- **Controller → Client (Seq i Reply)**  
  ```
  IP Header (20 bytes)
  └─ ICMP Header (8 bytes): Type=0, Code=0, ID=<PID>, Seq=i
     └─ Payload (<=500 bytes): [“RQ47”][up to 496 bytes of data]
  ```

- **Client → Controller (Seq i Request, after C2 payload)**  
  ```
  IP Header (20 bytes)
  └─ ICMP Header (8 bytes): Type=8, Code=0, ID=<PID>, Seq=i
     └─ Payload (<=500 bytes): [“RQ47”][up to 496 bytes of beacon/command data]
  ```

- **Controller → Client (Seq i Reply, TeamServer data)**  
  ```
  IP Header (20 bytes)
  └─ ICMP Header (8 bytes): Type=0, Code=0, ID=<PID>, Seq=i
     └─ Payload (<=500 bytes): [“RQ47”][TeamServer response data]
  ```

---

## Advantages & Caveats

- **Quietness**: Leverages legitimate ICMP traffic.  
- **Minimal Dependencies**: Only raw sockets and basic ICMP parsing.  
- **Fragility**: No built-in session encryption or integrity checks—relying solely on the 4-byte TAG for filtering.  
- **IDS/Firewall Risk**: Large or unusual ICMP payloads may trigger alerts. Payloads are chunked to 496 bytes to avoid fragmentation, but the TAG may still look suspicious.

---

## Usage Notes

1. **Client setup**: Must open a raw ICMP socket with permission.  
2. **Controller setup**: Needs elevated privileges to sniff and send raw ICMP.  
3. **Tag matching**: Both sides ignore any ICMP not starting with `RQ47`, preventing OS replies from disrupting reassembly.  
4. **Timeouts**: The client’s recv loop should have a timeout (e.g. 5 seconds) to abort if fragments never arrive.  
5. **TeamServer traffic**: After the initial C2 payload, any “seq > 0” Echo Requests are forwarded to the TeamServer over plain TCP; replies come back in a single ICMP Echo 