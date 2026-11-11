from scapy.all import IP, UDP, TCP, DNS, DNSQR, Raw, wrpcap

packets = []

# DNS packets
for domain in ["example.com", "google.com", "example.com"]:
    pkt = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    packets.append(pkt)

# HTTP packets with Host header
for host in ["example.com", "neverssl.com"]:
    payload = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    pkt = IP(dst="93.184.216.34") / TCP(dport=80) / Raw(load=payload)
    packets.append(pkt)

# Beaconing: 6 packets to same IP, ~10 seconds apart
base_time = 1700000000.0
for i in range(6):
    pkt = IP(dst="10.0.0.99") / TCP(dport=443)
    pkt.time = base_time + (i * 10)
    packets.append(pkt)

wrpcap("test.pcap", packets)
print("Wrote test.pcap with", len(packets), "packets")
