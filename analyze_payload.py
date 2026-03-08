from scapy.all import rdpcap, IP, UDP, Raw
import binascii

packets = rdpcap("PCAPdroid_09_Mar_03_22_03.pcap")

server_ip = '45.135.228.80'
client_ip = '192.168.1.8'
server_port = 5056
client_port = 49800

payloads = []

for pkt in packets:
    if IP in pkt and UDP in pkt and Raw in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

        if (src == client_ip and dst == server_ip) or (src == server_ip and dst == client_ip):
            payload = bytes(pkt[Raw].load)
            payload_hex = binascii.hexlify(payload).decode('utf-8')
            direction = "Client -> Server" if src == client_ip else "Server -> Client"

            payloads.append({
                'direction': direction,
                'len': len(payload),
                'hex': payload_hex,
                'ascii': ''.join([chr(b) if 32 <= b <= 126 else '.' for b in payload])
            })

print(f"Total UDP game packets with payload: {len(payloads)}")

# Group payloads by first few bytes to identify packet types
from collections import Counter
c2s_types = Counter()
s2c_types = Counter()

for p in payloads:
    if p['len'] > 0:
        first_byte = p['hex'][:2]
        if p['direction'] == "Client -> Server":
            c2s_types[first_byte] += 1
        else:
            s2c_types[first_byte] += 1

print("\nClient -> Server Packet Types (first byte):")
for t, count in c2s_types.most_common(10):
    print(f"Type {t}: {count}")

print("\nServer -> Client Packet Types (first byte):")
for t, count in s2c_types.most_common(10):
    print(f"Type {t}: {count}")

print("\nSample Client -> Server payloads:")
for p in [x for x in payloads if x['direction'] == 'Client -> Server'][:5]:
    print(f"Length {p['len']}: {p['hex'][:64]}... | {p['ascii'][:32]}")

print("\nSample Server -> Client payloads:")
for p in [x for x in payloads if x['direction'] == 'Server -> Client'][:5]:
    print(f"Length {p['len']}: {p['hex'][:64]}... | {p['ascii'][:32]}")
