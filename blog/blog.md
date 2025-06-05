---
title: Cobalt Strike - Implementing ICMP using External C2
date: 2025-06-05 00:00:01 +0600
categories: [Tools, Cobalt-Strike, Malware]
tags: [tools, cobalt-strike, malware]     # TAG names should always be lowercase
---

# Cobalt Strike External C2 & A Beacon ICMP Layer

Being able to build your own C2 layers has always fascinated me - and you can imagine my excitement when I discovered the ability to do this with Cobalt Strike's External C2 - so I decided to explore it a bit!

### Initial Idea:

Initially, I just wanted to experiment with External C2 and explore what it was capable of. While working through the example provided by [Fortra](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/extc2example.c), I had the idea to try building my own communication layer. I’d been wanting to build a C2 channel over ICMP—as the C2 matrix shows only two existing implementations (INNUENDO and Nighthawk) —and this project offered the perfect opportunity to do it.

Of all the ICMP message types, I settled on Echo Request (Type 8) and Echo Reply (Type 0), as they offer several advantages:

- **Broad network allowance**
  ICMP Echo messages are commonly permitted in many network environments—especially for outbound traffic—making them less likely to be blocked compared to custom TCP or UDP ports.
- **Built-in fields**
  Echo Request and Reply messages include simple but useful fields like an identifier, sequence number, and a payload. These can be leveraged for lightweight messaging, tracking, and sequencing in a basic C2 channel. While limited in structure, they are sufficient for simple tasks like beaconing or command polling.
- **Native OS support**
  Virtually every operating system—including Windows, macOS, and Linux—has a built-in ICMP stack. You don’t need special libraries or drivers to send and receive ICMP packets.

### Implementation

All the uber technical details can be found [here](https://github.com/ryanq47/CS-EXTC2-ICMP), in the readme of my repo.

For reference, here's the External C2 flow diagram provided by Fortra.

![Cobalt Strike External C2 Flow](https://www.mdsec.co.uk/wp-content/uploads/2019/02/extc2.png)

At a 10,000-foot view, the client:

1. **Asks the Controller for a Beacon binary.**
2. **Runs that Beacon in memory and pipes traffic through itself.**
3. **Proxies Beacon traffic between the Controller and TeamServer.**

Pretty typical stuff. However, the difference here is that it's mapped to commnicate over ICMP:

1. The Client embeds data in an **Echo Request** and sends it to the Controller.
2. The Controller embeds a response in an **Echo Reply** and sends it back.

Super simple, but it enables a communication channel by only using outbound ICMP.

#### ICMP_PAYLOAD_SIZE = 1000

In both `client_x86.c` and `controller.py`, we hardcode:

```c
#define ICMP_PAYLOAD_SIZE 1000
#define TAG_SIZE          4      // “RQ47”
```

That means each ICMP packet’s **data field** can hold up to **1000 bytes**. Of those 1000 bytes, the first 4 bytes are always the TAG (`RQ47`). Consequently:

- **Max data per chunk = 1000 – 4 = 996 bytes.**

> *If you want smaller chunks (e.g. to mimic a standard Windows ping (32 bytes), or unix ping  52 bytes)), you can change `ICMP_PAYLOAD_SIZE` (and update both client & controller). I went with 1000 to optimize bulk transfers & not take forever while debugging.*

> **On-the-wire packet size** = 20 bytes (IP header) + 8 bytes (ICMP header) + 1000 bytes (data) = **1028 bytes**.

> clean this up: simple it down:

## How the Client & Controller Work, Step by Step

Note: Using default of `1000` bytes as the payload size in this example. If you change your payload size to `32`, it'll only be 32 bytes (or 28 if you subtract the tag), per chunk.

1. **Client Initialization (Requesting a Beacon)**

   - The client opens a raw ICMP socket and prepares to communicate with the controller.
   - To request a fresh Beacon, the client sends a chunked ICMP Echo Requests, quite literally saying `I WANT A PAYLOAD`: (please change this if using this and actually trying to be quiet, I included it because I thought it was funny)

     1. **Seq 0** – “Length only” packet:
        ```
        [ ICMP Echo Request (Type 8), Seq=0 ]
        Payload = [ “RQ47” (4 bytes) ] [ 4-byte big-endian integer: len("I WANT A PAYLOAD") ]
        ```
     2. **Seq 1** – “Command” packet:
        ```
        [ ICMP Echo Request (Type 8), Seq=1 ]
        Payload = [ “RQ47” (4 bytes) ] [ “I WANT A PAYLOAD” (17 bytes) ]
        ```

     - The controller’s listener will see Seq 0 first and record that it should expect 17 bytes. Immediately afterward, Seq 1 carries the `I WANT A PAYLOAD` command.
2. **Controller Receives the Request**

   - The controller’s sniffer detects the ICMP Echo Request with **Seq 0**:
     ```
     [ ICMP Echo Request (Type 8), Seq=0 ]
     Payload starts with “RQ47”, next 4 bytes = 17
     ```
   - It notes that "size sent by seq 0 packet" (in this case, 17) bytes should follow. A handler thread is created (or updated) for this client IP + ICMP ID.
   - That handler then waits for the next packet(s) until exactly 17 bytes (the special command) arrive.
3. **Controller Reads “I WANT A PAYLOAD” (Seq 1)**

   - The handler sees the ICMP Echo Request with **Seq 1**:
     ```
     [ ICMP Echo Request (Type 8), Seq=1 ]
     Payload starts with “RQ47”, next 17 bytes = "I WANT A PAYLOAD"
     ```
   - Upon recognizing the exact string `I WANT A PAYLOAD`, the controller connects to Cobalt Strike’s TeamServer, performs the handshake, and retrieves the Beacon binary.
   - Once the Beacon bytes are obtained, the controller is ready to send them back to the client.
4. **Controller → Client: Sending the Beacon (Seq 0 → Seq N)**

   - Before transmitting the actual Beacon data back to the client, the controller announces its total size:

     1. **Seq 0 (Echo Reply)**
        ```
        [ ICMP Echo Reply (Type 0), Seq=0 ]
        Payload = [ “RQ47” (4 bytes) ] [ 4-byte big-endian integer: beacon_length ]
        ```

     - Next, the controller splits the Beacon into chunks of up to 996 bytes each (because 1000 bytes total minus the 4 byte TAG). For each chunk numbered i = 1…N:

       2. **Seq i (Echo Reply)**

       ```
       [ ICMP Echo Reply (Type 0), Seq=i ]
       Payload = [ “RQ47” (4 bytes) ] [ up to 996 bytes of Beacon data (chunk i) ]
       ```

       - For example, if the Beacon is 1456 bytes long:
         - Seq 0 → `[RQ47][0x000005B0]`  (0x5B0 = 1456)
         - Seq 1 → `[RQ47][ first 996 bytes ]`
         - Seq 2 → `[RQ47][ remaining 460 bytes ]`
5. **Client Reassembles & Runs the Beacon**

   - The client sends out ICMP Echo Requests, and listens for ICMP Echo Replies (which contain the beacon data). Upon getting a return **Seq 0**:

     ```
     [ ICMP Echo Reply (Type 0), Seq=0 ]
     Payload starts with “RQ47”, next 4 bytes = total_size (e.g., 1456)
     ```
   - It allocates a buffer of that exact length and calculates how many chunks it must receive (`ceil(total_size / 996)`).
   - As each subsequent Echo Reply arrives (Seq 1, Seq 2, …), the client strips off the 4-byte tag and copies the data portion into the correct offset in its buffer. Once all chunks are in place, the client has the full Beacon binary.
   - Finally, the client allocates executable memory, copies the Beacon bytes into it, switches permissions to execute, and spawns a thread to run the Beacon entirely in memory.

     - > If the client gets caught by AV/EDR - it's likely going to be here
       >
6. **Beacon Proxying (Ongoing Communication, Seq > 0)**

   - After the Beacon is running, it communicates over a named pipe (e.g., `\\.\pipe\foobar`). Whenever the Beacon writes a frame into that pipe (length + payload), the client again uses the same chunked ICMP pattern to get data back and forth:
     1. **Seq 0** – Announce “next frame length”
        ```
        [ ICMP Echo Request (Type 8), Seq=0 ]
        Payload = [ “RQ47” (4 bytes) ] [ 4-byte big-endian integer: frame_length ]
        ```
     2. **Seq 1…M** – Send up to 996 bytes of frame data per packet:
        ```
        [ ICMP Echo Request (Type 8), Seq=i ]
        Payload = [ “RQ47” (4 bytes) ] [ up to 996 bytes of pipe data ]
        ```
   - Each handler thread on the controller side reads those fragments, reassembles the full frame, and forwards it to the TeamServer over TCP.
   - Any response from the TeamServer is immediately broken into chunks (≤ 996 bytes), and the controller sends them back as ICMP Echo Replies with the corresponding sequence numbers.
   - The client reassembles those replies in the same manner and writes them into the Beacon’s named pipe. This loop continues until the Beacon or client is terminated.

---

### Challenges

#### Chunking:

Chunking was *by far* the hardest part of this entire project. Figuring out a good protocol setup that allowed for bi-directional comms over ICMP with variable length payloads took a majority of the time.

The original POC sent only one ICMP packet at a time, which limited the maximum payload to 1472 bytes (MTU 1500 – 20 byte IPv4 header – 8 byte ICMP header). That worked for small transfers, like running `ls`—but anything “fun”, such as trying to run Mimikatz, would fail because the data sent to the beacon exceeded that single-packet limit. Plus, it's loud as hell, could potentially lead to ping of death with some weird fragmenting, and not flexible at all.

Luckily, after thinking it through and getting some help from good old ChatGPT, I was able to implement the chunking protocol described above and get it working—and it works great! It’s completely transparent to the Beacon and fairly flexible, especially thanks to the provided configuration options.

### See It in Action

I always get frustrated when README files or blogs don’t actually show a tool in action—so here’s a video demonstrating it working:
 
<video src="/assets/vid/cs_icmp_tunnel.mkv" width="720" height="480" controls></video>


### Future Objectives:

Below are a few areas I plan to explore next:

1. Hardened Client with Evasion Techniques

I want to build a more resilient client that incorporates proven evasion techniques. Right now, it makes no attempt at stealth and is quickly detected by modern EDR solutions. Even adding basic evasion techniques such as anti-debug checks and using dynamic function resolution would be a vast improvement over the current design.


2. Cobalt Strike Add-On for Uncommon Protocols

Additioanlly, I'd like to transform this work into a full Cobalt Strike extension that supports a wider range of protocols beyond the defaults. While the built–in channels cover most use cases, they often feel predictable and are heavily fingerprinted. Adding niche or custom protocols sounds like a really cool project, and may actually get used by someone!

### Resources
The link to this project's repo is here:

[Github: CS-EXTC2-ICMP](https://github.com/ryanq47/CS-EXTC2-ICMP)


Here are some additional resources I found helpful while working on this project:

[Fortra - CobaltStrike External C2](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_external-c2.htm)

[XPN Infosec Blog - Exploring Cobalt Strike's ExternalC2 framework](https://blog.xpnsec.com/exploring-cobalt-strikes-externalc2-framework/)

[Wikipedia ICMP Overview](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol)

[The C2 Matrix | C2 Matrix](https://howto.thec2matrix.com/)



