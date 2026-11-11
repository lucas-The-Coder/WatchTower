# FILE: packet_lens.py - PacketLens, Traffic Analyzer
# IDEA: Read a PCAP, pull DNS queries, HTTP hosts, and flag possible beaconing

# IMPORTS:
# sys - to take PCAP file path from command line
# json - to save report to packet_report.json
# collections - to group packets by IP and count
# datetime - to parse packet times and check intervals
# scapy - to read PCAP and parse packets, DNS, IP, TCP, Raw
import sys
import json
import collections
from datetime import datetime
from scapy.all import rdpcap, DNS, DNSQR, IP, TCP, UDP, Raw, Scapy_Exception, IP
from collections import defaultdict


# FUNCTION: parse_pcap(file_path)
# INPUT: file_path - string, e.g. "sample.pcap"
# OUTPUT: packets - list, each item is a Scapy packet
# STEP 1: Start with packets as empty list
# STEP 2: Try to read file with rdpcap, with try and except
# STEP 3: If file missing or read fails, make empty list and return packets
# STEP 4: If read works, return packets list
# STEP 5: Return packets
def parse_pcap(file_path):
    packets = []

    try:
        packets = rdpcap(file_path)

    except Exception as e:
        return []

    return packets


# FUNCTION: extract_dns(packets)
# INPUT: packets - list from parse_pcap
# OUTPUT: findings - list of dicts, each finding has check, severity, message
# STEP 1: Start with findings as empty list
# STEP 2: Start with seen_dns as empty set to avoid duplicates
# STEP 3: Loop each packet in packets
# STEP 4: If packet has DNS and DNSQR layer, get query name
# STEP 5: If query name not in seen_dns, add to seen_dns
# STEP 6: Build finding dict with check DNS query, severity INFO, message query name
# STEP 7: Append finding dict to findings
# STEP 8: Return findings
def extract_dns(packets):
    findings = []
    seen_dns = set()

    for pkt in packets:

        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")

            if qname not in seen_dns:
                seen_dns.add(qname)

                finding = {"check": "DNS query", "severity": "INFO", "message": qname}

                findings.append(finding)

    return findings


# FUNCTION: extract_http_hosts(packets)
# INPUT: packets - list from parse_pcap
# OUTPUT: findings - list of dicts, each finding has check, severity, message
# STEP 1: Start with findings as empty list
# STEP 2: Start with seen_hosts as empty set to avoid duplicates
# STEP 3: Loop each packet in packets
# STEP 4: If packet has Raw layer, decode payload to string with errors ignore
# STEP 5: If payload contains Host: then get host value after Host:
# STEP 6: If host not in seen_hosts, add to seen_hosts
# STEP 7: Build finding dict with check HTTP host, severity INFO, message host
# STEP 8: Append finding dict to findings
# STEP 9: Return findings
def extract_http_hosts(packets):
    findings = []
    seen_hosts = set()

    for pkt in packets:

        if pkt.haslayer(Raw):
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")

            if "Host:" in payload:
                for line in payload.splitlines():

                    if line.startswith("Host:"):
                        host = line.split("Host:", 1)[1].strip()

                        if host and host not in seen_hosts:
                            seen_hosts.add(host)

                            finding = {
                                "check": "HTTP host",
                                "severity": "INFO",
                                "message": host,
                            }

                            findings.append(finding)

    return findings


# FUNCTION: detect_beaconing(packets)
# INPUT: packets - list from parse_pcap
# OUTPUT: findings - list of dicts, each finding has check, severity, message
# STEP 1: Start with findings as empty list
# STEP 2: Group packet times by destination IP using collections.defaultdict list
# STEP 3: Loop each packet, if packet has IP layer, get dst IP and packet time
# STEP 4: Append packet time to list for that dst IP
# STEP 5: For each dst IP, sort times, check if 5 or more packets
# STEP 6: Calculate intervals between packets, check if intervals are similar, within 5 seconds of each other
# STEP 7: If similar and count 5 or more, build finding with severity HIGH, message Possible beaconing to dst IP
# STEP 8: Append finding dict to findings
# STEP 9: Return findings
def detect_beaconing(packets):
    findings = []

    ip_times = defaultdict(list)

    for pkt in packets:

        if pkt.haslayer(IP):
            dst_ip = pkt[IP].dst
            pkt_time = float(pkt.time)

            ip_times[dst_ip].append(pkt_time)

    for dst_ip, times in ip_times.items():

        if len(times) >= 5:
            times.sort()

            intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]

            if max(intervals) - min(intervals) <= 5:

                finding = {
                    "check": "Beaconing",
                    "severity": "HIGH",
                    "message": f"Possible beaconing to {dst_ip}",
                }

                findings.append(finding)

    return findings


# FUNCTION: main()
# STEP 1: Check sys.argv, if no PCAP given, print usage and stop
# STEP 2: Get PCAP file path from sys.argv, it is a string
# STEP 3: Call parse_pcap to get packets
# STEP 4: Call extract_dns to get DNS findings
# STEP 5: Call extract_http_hosts to get HTTP findings
# STEP 6: Call detect_beaconing to get beaconing findings
# STEP 7: Combine all finding lists into one list
# STEP 8: Save combined list to packet_report.json with try and except
# STEP 9: Loop each finding and print it
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 packet_lens.py <file.pcap>")

        return

    file_path = sys.argv[1]

    packets = parse_pcap(file_path)

    dns_findings = extract_dns(packets)

    http_findings = extract_http_hosts(packets)

    beacon_findings = detect_beaconing(packets)

    all_findings = dns_findings + http_findings + beacon_findings

    try:
        with open("packet_report.json", "w") as f:
            json.dump(all_findings, f, indent=4)

    except Exception as e:
        print(f"failed to save report: {e}")

    for finding in all_findings:
        print(f"[{finding['severity']}] {finding['check']}: {finding['message']}")


# BOTTOM: Call main()
if __name__ == "__main__":
    main()
