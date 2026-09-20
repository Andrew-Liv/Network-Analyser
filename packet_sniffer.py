from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
import argparse

protocol_counts = Counter()
source_ip_counts = Counter()
destination_ip_counts = Counter()

packet_sizes = []

packet_records = []

packet_count = 0


def identify_service(port):
    services = {
        20: "FTP",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        443: "HTTPS",
        445: "SMB",
    }

    return services.get(port, "-")


def packet_callback(packet, selected_protocol=None, selected_port=None):
    global packet_count

    # Ignore packets that don't contain IPv4
    if IP not in packet:
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst
    packet_size = len(packet)

    if TCP in packet:
        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"
        source_port = "-"
        destination_port = "-"

    else:
        protocol = "OTHER"
        source_port = "-"
        destination_port = "-"

    # Ignore packets that don't match the selected protocol
    if selected_protocol and protocol != selected_protocol:
        return

    # Ignore packets that don't match the selected port
    if selected_port:
        if protocol not in ["TCP", "UDP"]:
            return

        if source_port != selected_port and destination_port != selected_port:
            return

    packet_count += 1

    # Identify service
    if protocol in ["TCP", "UDP"]:
        source_service = identify_service(source_port)
        destination_service = identify_service(destination_port)
    else:
        source_service = "-"
        destination_service = "-"

    # Update statistics
    protocol_counts[protocol] += 1
    source_ip_counts[source_ip] += 1
    destination_ip_counts[destination_ip] += 1
    packet_sizes.append(packet_size)

    # Create packet record
    packet_record = (
        f"{protocol:<6} "
        f"{source_ip:<15} -> "
        f"{destination_ip:<15} "
        f"{str(source_port):<6} -> "
        f"{str(destination_port):<6} "
        f"{source_service:<8} -> "
        f"{destination_service:<8} "
        f"{packet_size} bytes"
    )

    packet_records.append(packet_record)

    print(packet_record)


def print_summary():
    print("\n" + "=" * 50)
    print("PACKET CAPTURE SUMMARY")
    print("=" * 50)

    print(f"Total IP packets analysed: {packet_count}\n")

    print("Protocol breakdown:")

    for protocol, count in protocol_counts.items():
        print(f"{protocol:<10}: {count}")

    print("\nTop source IPs:")

    for ip, count in source_ip_counts.most_common(5):
        print(f"{ip:<18}: {count}")

    print("\nTop destination IPs:")

    for ip, count in destination_ip_counts.most_common(5):
        print(f"{ip:<18}: {count}")

    print("\nPacket size statistics:")

    total_bytes = sum(packet_sizes)
    average_size = total_bytes / len(packet_sizes)
    largest_packet = max(packet_sizes)
    smallest_packet = min(packet_sizes)

    print(f"Total data captured : {total_bytes} bytes")
    print(f"Average packet size : {average_size:.2f} bytes")
    print(f"Largest packet      : {largest_packet} bytes")
    print(f"Smallest packet     : {smallest_packet} bytes")


def save_report(filename):
    with open(filename, "w") as report:

        report.write("=" * 70 + "\n")
        report.write("        PYTHON NETWORK PACKET ANALYSER REPORT\n")
        report.write("=" * 70 + "\n\n")

        report.write("PACKET DATA\n")
        report.write("-" * 70 + "\n")

        for record in packet_records:
            report.write(record + "\n")

        report.write("\n")
        report.write("=" * 50 + "\n")
        report.write("PACKET CAPTURE SUMMARY\n")
        report.write("=" * 50 + "\n")

        report.write(
            f"Total IP packets analysed: {packet_count}\n\n"
        )

        report.write("Protocol breakdown:\n")

        for protocol, count in protocol_counts.items():
            report.write(f"{protocol:<10}: {count}\n")

        report.write("\nTop source IPs:\n")

        for ip, count in source_ip_counts.most_common(5):
            report.write(f"{ip:<18}: {count}\n")

        report.write("\nTop destination IPs:\n")

        for ip, count in destination_ip_counts.most_common(5):
            report.write(f"{ip:<18}: {count}\n")

        report.write("\nPacket size statistics:\n")

        total_bytes = sum(packet_sizes)
        average_size = total_bytes / len(packet_sizes)
        largest_packet = max(packet_sizes)
        smallest_packet = min(packet_sizes)

        report.write(
            f"Total data captured : {total_bytes} bytes\n"
        )
        report.write(
            f"Average packet size : {average_size:.2f} bytes\n"
        )
        report.write(
            f"Largest packet      : {largest_packet} bytes\n"
        )
        report.write(
            f"Smallest packet     : {smallest_packet} bytes\n"
        )


def main():

    parser = argparse.ArgumentParser(
        description="Python Network Packet Analyser"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of packets to analyse"
    )

    parser.add_argument(
        "--protocol",
        choices=["TCP", "UDP", "ICMP"],
        help="Only analyse a specific protocol"
    )

    parser.add_argument(
        "--port",
        type=int,
        help="Only analyse traffic using a specific port"
    )

    parser.add_argument(
        "--output",
        type=str,
        help="Save the analysis report to a text file"
    )

    args = parser.parse_args()

    print("=" * 50)
    print("        PYTHON NETWORK PACKET ANALYSER")
    print("=" * 50)

    if args.protocol and args.port:
        print(
            f"Analysing {args.count} {args.protocol} packets "
            f"using port {args.port}..."
        )

    elif args.protocol:
        print(f"Analysing {args.count} {args.protocol} packets...")

    elif args.port:
        print(
            f"Analysing {args.count} packets using port {args.port}..."
        )

    else:
        print(f"Analysing {args.count} packets...")

    if args.output:
        print(f"Report will be saved to: {args.output}")

    print("Press CTRL+C to stop.\n")

    while packet_count < args.count:
        sniff(
            prn=lambda packet: packet_callback(
                packet,
                args.protocol,
                args.port
            ),
            store=False,
            count=1
        )

    print("\nCapture complete!")

    print_summary()

    if args.output:
        save_report(args.output)
        print(f"\nReport saved to: {args.output}")


if __name__ == "__main__":
    main()