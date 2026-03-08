from scapy.all import rdpcap, IP, UDP, Raw
import binascii
import os

packets = rdpcap("PCAPdroid_09_Mar_03_22_03.pcap")

server_ip = '45.135.228.80'
client_ip = '192.168.1.8'

with open("payload_dump.md", "w") as f:
    f.write("# Dump Payload Paket (UDP Client <-> Server)\n\n")

    for i, pkt in enumerate(packets):
        if IP in pkt and UDP in pkt and Raw in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst

            if (src == client_ip and dst == server_ip) or (src == server_ip and dst == client_ip):
                payload = bytes(pkt[Raw].load)
                payload_hex = binascii.hexlify(payload).decode('utf-8')

                # Format hex payload like a hexdump
                formatted_hex = ""
                for j in range(0, len(payload_hex), 32): # 16 bytes per line
                    chunk_hex = payload_hex[j:j+32]
                    chunk_bytes = binascii.unhexlify(chunk_hex)

                    hex_str = " ".join([chunk_hex[k:k+2] for k in range(0, len(chunk_hex), 2)])
                    ascii_str = "".join([chr(b) if 32 <= b <= 126 else '.' for b in chunk_bytes])

                    formatted_hex += f"{hex_str:<48} | {ascii_str}\n"

                direction = "Client (192.168.1.8) -> Server (45.135.228.80)" if src == client_ip else "Server (45.135.228.80) -> Client (192.168.1.8)"

                f.write(f"### Paket #{i+1} | {direction} | Length: {len(payload)} bytes\n")
                f.write("```text\n")
                f.write(formatted_hex)
                f.write("```\n\n")

print("Payload dump saved to payload_dump.md")
