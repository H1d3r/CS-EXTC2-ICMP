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

All the uber technical details can be found [here](https://github.com/ryanq47/CS-EXTC2-ICMP, in the readme of my repo.

For reference, here's the External C2 flow diagram provided by Fortra.

![Cobalt Strike External C2 Flow](https://www.mdsec.co.uk/wp-content/uploads/2019/02/extc2.png)

At a high level, the execution flow of the client operates in accordance with the above picture:

1. Client asks for payload from Controller
2. The Client runs the payload, and interfaces with the Beacon
3. The Client turns into a proxy between the Controller and Beacon

As for getting that data between the Client & Controller:

1. The Client embeds data into an Echo Request and sends to the Controller
2. The Controller embeds a response into the Echo Reply, and responds to the Clients Echo Request

Getting into it, here’s how the client and controller interact in practice:

Lets assume that the `ICMP_PAYLOAD_SIZE` is set to 500 bytes.

> This means that the data/payload field of each ICMP packet will be 500 bytes (4 for tag, 496 for data).
>
> Total packet size will be ICMP_PAYLOAD_SIZE + 8 (ICMP header) + 20 (IPV4) Header = 528 Bytes

1. **Client Initialization**
   The client starts by opening a raw ICMP socket and preparing to communicate with the controller. It embeds a short  message into an **ICMP Echo Request (Type 8)** — this message includes a custom 4-byte tag (`RQ47`) and a 4-byte integer indicating how much data the client expects to receive (e.g., the Beacon payload size). This is sent with **sequence number 0**. Sequence 0 == Give me payload.
2. **Controller Acknowledgment**
   When the controller receives this specially crafted Echo Request, it verifies the `RQ47` tag and confirms the request by replying with an **ICMP Echo Reply (Type 0)**, also tagged and marked as **sequence 0**. The reply includes the total size of the payload to be delivered back to the client.
3. **Payload Delivery (Controller → Client)**
   The controller breaks the payload into 496-byte* chunks (to avoid fragmentation issues) and sends each as a separate Echo Reply with **increasing sequence numbers** (starting at 1). Each reply is tagged (`RQ47`) and carries its slice of data.

   > *assuming ICMP_PAYLOAD_SIZE is 500 as stated above. To get chunk size, do `ICMP_PAYLOAD_SIZE - 4`
   >
4. **Payload Reassembly & Execution (Client)**
   The client receives the sequence of replies, validates the tag, and reassembles the payload using the sequence numbers. Once all expected fragments have arrived, the full payload (a Beacon) is written to memory and executed.
5. **Beacon Proxying**

   After launching the Beacon, the client enters a loop where it acts as a transparent proxy:

   - Any Beacon output is wrapped in an **ICMP Echo Request** with `RQ47` and a sequence number > 0.
   - The controller unwraps this data and forwards it to the Cobalt Strike TeamServer over a local TCP connection.
   - Responses from the TeamServer are wrapped in Echo Replies and sent back to the client, again tagged and sequenced.

### In Practice

`<images of it running>` (& basic setup?)

- [ ] Talk about default windows/linux icmp values, and adjustable parameters.

### Going forward goals:

- [ ] A better written version of the cliente.exe, with evasion techniques added on. Current client.c dones't event try to evade.

### Resources

Here are resources I found helpful while working on this project:

[Fortra - CobaltStrike External C2](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_external-c2.htm)

[XPN Infosec Blog - Exploring Cobalt Strike's ExternalC2 framework](https://blog.xpnsec.com/exploring-cobalt-strikes-externalc2-framework/)

[Wikipedia ICMP Overview](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)
