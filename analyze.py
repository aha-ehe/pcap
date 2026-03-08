from scapy.all import rdpcap, IP, UDP, TCP, DNSQR, Raw
from collections import Counter

packets = rdpcap("PCAPdroid_09_Mar_03_22_03.pcap")

print(f"Total packets: {len(packets)}")

dns_queries = set()
flows = Counter()
protocols = Counter()

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto

        if proto == 6 and TCP in pkt: # TCP
            flows[(src, dst, 'TCP', pkt[TCP].dport)] += 1
            protocols['TCP'] += 1
        elif proto == 17 and UDP in pkt: # UDP
            flows[(src, dst, 'UDP', pkt[UDP].dport)] += 1
            protocols['UDP'] += 1
            if pkt.haslayer(DNSQR):
                dns_queries.add(pkt[DNSQR].qname.decode(errors='ignore'))
        else:
            protocols[f'Proto {proto}'] += 1

print("DNS Queries:")
for q in dns_queries:
    print(f" - {q}")

print("\nTop Flows:")
for flow, count in flows.most_common(10):
    print(f"{flow[0]} -> {flow[1]} ({flow[2]} port {flow[3]}): {count} packets")

print("\nProtocols:")
for p, count in protocols.most_common():
    print(f"{p}: {count}")
