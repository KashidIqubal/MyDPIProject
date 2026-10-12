from scapy.all import rdpcap, IP, TCP, UDP
from collections import Counter
import csv

print("=" * 45)
print("          DPI PACKET ANALYZER")
print("=" * 45)

file_path = input("Enter the path of a .pcap or .pcapng file: ")

try:
    packets = rdpcap(file_path)

    print(f"\nTotal packets captured: {len(packets)}")
    print("-" * 75)

    protocol_counts = Counter()
    packet_results = []

    for number, packet in enumerate(packets, start=1):
        if IP in packet:
            source = packet[IP].src
            destination = packet[IP].dst
            source_port = "-"
            destination_port = "-"
            protocol = "Other"

            if TCP in packet:
                source_port = packet[TCP].sport
                destination_port = packet[TCP].dport

                if source_port == 80 or destination_port == 80:
                    protocol = "HTTP"
                elif source_port == 443 or destination_port == 443:
                    protocol = "HTTPS"
                else:
                    protocol = "TCP"

            elif UDP in packet:
                source_port = packet[UDP].sport
                destination_port = packet[UDP].dport

                if source_port == 53 or destination_port == 53:
                    protocol = "DNS"
                else:
                    protocol = "UDP"

            protocol_counts[protocol] += 1
            packet_results.append({
                "Packet Number": number,
                "Source IP": source,
                "Destination IP": destination,
                "Source Port": source_port,
                "Destination Port": destination_port,
                "Protocol": protocol,
                "Packet Size": len(packet)
            })

            print(
                f"Packet {number}: "
                f"{source}:{source_port} -> "
                f"{destination}:{destination_port} | "
                f"{protocol} | "
                f"Size: {len(packet)} bytes"
            )

        else:
            protocol_counts["Non-IPv4"] += 1
            print(
                f"Packet {number}: Non-IPv4 packet | "
                f"Size: {len(packet)} bytes"
            )

    print("\n" + "=" * 45)
    csv_file = "packet_analysis.csv"

    with open(csv_file, "w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "Packet Number",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Protocol",
            "Packet Size"
        ]

        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(packet_results)

    print(f"CSV report saved as: {csv_file}")
    print("             PACKET SUMMARY")
    print("=" * 45)
    print(f"Total packets: {len(packets)}")

    for protocol, count in sorted(protocol_counts.items()):
        print(f"{protocol} packets: {count}")
    tcp_count = sum(1 for packet in packets if TCP in packet)
    udp_count = sum(1 for packet in packets if UDP in packet)

    print(f"TCP packets: {tcp_count}")
    print(f"UDP packets: {udp_count}")

    print("\nApplication categories:")
    for protocol, count in sorted(protocol_counts.items()):
        print(f"{protocol}: {count}")
    print("=" * 45)

except FileNotFoundError:
    print("Error: File not found. Check the file path.")

except Exception as error:
    print(f"Error reading capture: {error}")