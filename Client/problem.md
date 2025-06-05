PROBLEM:

I think the problem is that the pipe has no data, and as such bugs out the logic, especially with the chunking.

Old iterations would just send the data back, no matter how big the size, which would allow it to proceed, and check in to teamserver?

So, I think thta I'll have to edit the contorller logic to be okay with a 0 size chunk:

[+] Sent ICMP REPLY seq=1, len=5
[+] New seq=0 packet received from 172.19.240.1, ID=6600
[+] seq=0 content: b''
[-] seq=0 payload too short to contain length