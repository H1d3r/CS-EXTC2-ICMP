# Cobalt Strike External C2 & A Beacon ICMP Layer

Being able to build your own C2 layers has always fascinated me - and you can imagine my excitement when I discovred the ability to do this with Cobalt Strike's External C2.

### Initial Idea

Initially, I just wanted to experiment with External C2 and explore what it was capable of. While working through the example provided by [Fortra](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/extc2example.c), I had the idea to try building my own communication layer. Implementing a C2 channel over ICMP had been on my mind for a while, and this seemed like the perfect opportunity to pursue it.

Of all the ICMP message types, Echo Request (Type 8) and Echo Reply (Type 0) offer several advantages:

- **Broad network allowance**
  ICMP Echo messages are commonly permitted in many network environments—especially for outbound traffic—making them less likely to be blocked compared to custom TCP or UDP ports.
- **Built-in fields**
  Echo Request and Reply messages include simple but useful fields like an identifier, sequence number, and a payload. These can be leveraged for lightweight messaging, tracking, and sequencing in a basic C2 channel. While limited in structure, they are sufficient for simple tasks like beaconing or command polling.
- **Native OS support**
  Virtually every operating system—including Windows, macOS, and Linux—has a built-in ICMP stack. You don’t need special libraries or drivers to send and receive ICMP packets.

### Implementation

- **ICMP Echo Request (Type 8)**: Used by the client (“agent”) to signal the server (“controller”) and request data.
- **ICMP Echo Reply (Type 0)**: Used by the controller to embed and send replies (including large payloads) back to the client.
- **TAG (4 bytes)**: A fixed 4-byte marker (e.g. `RQ47`) prepended to every ICMP payload, so that unrelated OS pings or network noise are ignored.
- **Chunking**: When the controller needs to send more data than fits in one ICMP packet (500 bytes), it splits the payload into multiple fragments. Each fragment still carries the same 4-byte tag.

### Resources

Here resources I found helpful while working on this project:

[Fortra - CobaltStrike External C2](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_external-c2.htm)

[XPN Infosec Blog - Exploring Cobalt Strike's ExternalC2 framework](https://blog.xpnsec.com/exploring-cobalt-strikes-externalc2-framework/)

[Wikipedia ICMP Overview](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
