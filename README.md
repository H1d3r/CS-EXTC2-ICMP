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

---

# ICMP C2 Channel


# ICMP Chunked Data Transfer Protocol (PoC)

## Overview
This project demonstrates a custom communication protocol built on ICMP Echo Request/Reply packets. It enables chunked message transmission using raw ICMP sockets and user-space control.

**Goal:** Quietly transfer messages over ICMP, chunked into smaller packets, while avoiding kernel interference.

---

## Packet Layout

### ICMP Echo Header (Standard)
| Field             | Size | Description                      |
|------------------|------|----------------------------------|
| Type             | 1 B  | 8 = Echo Request, 0 = Reply      |
| Code             | 1 B  | Always 0                         |
| Checksum         | 2 B  | Checksum of ICMP header + data   |
| Identifier (ID)  | 2 B  | Used to match request/reply      |
| Sequence Number  | 2 B  | Incremented each packet          |

### Custom Payload Layout
| Field             | Size | Description                         |
|------------------|------|-------------------------------------|
| Tag              | 4 B  | Magic tag (e.g., "RQ47")             |
| Chunk Index      | 4 B  | Big-endian uint32 (per chunk)       |
| Total Chunks     | 4 B  | Big-endian uint32                   |
| Data             | Var. | Message slice                       |

Minimum payload size = 13 bytes. Maximum typically ~1472 bytes (MTU - headers).

A packet consists the Header + Payload Layout

---

## C2 Flow (Client → Server)

```plaintext
[Agent]                          [C2 Server]
   |                                   |
   | --- ICMP Echo Request (chunk) --> |
   |                                   |
   | <-- ICMP Echo Reply (ack) ------- |
   |                                   |
```

1. Client sends chunks via ICMP Echo Request.
2. Server reassembles the full message.
3. Server sends an Echo Reply with a status message/tag.

---

## Client Logic (C, Windows)
- Sends ICMP Echo Requests using raw socket
- Splits message into `chunk_size = ICMP_PAYLOAD_SIZE - 12`
- Fills each packet with:
  - 4B Tag (e.g. "RQ47")
  - 4B Chunk Index
  - 4B Total Chunk Count
  - Message Slice
- Uses `htons()` and `htonl()` for byte order compliance
- Delays between sends to avoid detection

### Example:
```c
memcpy(payload, ICMP_TAG, 4);
memcpy(payload + 4, &chunk_index_net, 4);
memcpy(payload + 8, &total_chunks_net, 4);
memcpy(payload + 12, chunk_data, chunk_size);
```

---

## Server Logic (Python + Scapy)
- Disables OS-level ICMP handling with:
  ```bash
  sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
  ```
- Listens for ICMP Echo Requests
- Extracts chunks, and reassembles full message once all chunks are received
- Sends back an ICMP Echo Reply with a placeholder tag, this will be used for data transfer

### Session Handling:
Each session is keyed by `(src_ip, icmp_id)`. A session tracks:
- Total expected chunks
- Individual chunk data
- Timestamp for expiration

---

## Notes & Caveats
- **ICMP Fragmentation:** Ensure payload stays < MTU (~1472 bytes total)
- **Detection Risk:** Avoid large burst patterns; include jitter or padding
- **OS Replies:** Must be disabled or filtered to avoid false responses
- **Tag Matching:** Replies must also include `RQ47` tag to be accepted by client

---

## Summary
This ICMP protocol enables silent, session-aware message passing via chunked Echo Requests. With raw socket control and tag-based filtering, it avoids OS ICMP interference and supports stealthy communication in restricted environments.
