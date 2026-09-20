# Python Network Traffic Analyser

A command-line network traffic analyser built with **Python** and **Scapy**. The project captures network packets in real time and extracts useful information such as IP addresses, protocols, ports, packet sizes and commonly associated services.

I built this project to develop my practical understanding of **network traffic analysis, packet structure and cybersecurity monitoring** using Python.

> **Note:** This project is intended for use on networks and devices that you own or have permission to monitor.

## Features

- Real-time packet capture
- IPv4 packet analysis
- TCP, UDP and ICMP detection
- Source and destination IP address identification
- Source and destination port identification
- Packet size analysis
- Protocol statistics
- Top source and destination IP statistics
- Protocol filtering
- Port filtering
- Common service identification
- Packet capture reports
- Command-line arguments for flexible analysis

## Technologies Used

- **Python**
- **Scapy**
- **Npcap** (Windows packet capture support)

## How It Works

The analyser uses Scapy to capture packets from the network interface. For each IPv4 packet, the program checks which protocol is being used and extracts relevant information.

For example, a TCP packet might be displayed as:

```text
TCP    192.0.2.10      -> 203.0.113.20    54321  -> 443    -        -> HTTPS    66 bytes
```

This shows:

- Protocol: TCP
- Source IP: `192.0.2.10`
- Destination IP: `203.0.113.20`
- Source port: `54321`
- Destination port: `443`
- Destination service: HTTPS
- Packet size: 66 bytes

The IP addresses shown above are documentation addresses used for example purposes.

## Installation

Clone the repository and install the required Python dependency:

```bash
pip install -r requirements.txt
```

The project uses Scapy for packet capture and analysis.

### Windows

On Windows, **Npcap** is required for packet capture.

After installing Npcap, the analyser can be run from a terminal using Python.

## Basic Usage

Run the analyser with:

```bash
python packet_sniffer.py
```

By default, the program analyses 100 matching IPv4 packets.

A smaller capture can be specified using `--count`:

```bash
python packet_sniffer.py --count 10
```

### Example Output

```text
==================================================
        PYTHON NETWORK PACKET ANALYSER
==================================================
Analysing 10 packets...
Press CTRL+C to stop.

TCP    192.0.2.10      -> 203.0.113.20    54321  -> 443    -        -> HTTPS    66 bytes
UDP    192.0.2.10      -> 203.0.113.53    54322  -> 53     -        -> DNS      74 bytes
ICMP   192.0.2.10      -> 203.0.113.53    -      -> -      -        -> -        98 bytes
```

## Protocol Detection

The analyser identifies three main protocols:

- TCP
- UDP
- ICMP

### TCP

TCP traffic can be filtered using:

```bash
python packet_sniffer.py --count 10 --protocol TCP
```

### UDP

UDP traffic can be filtered using:

```bash
python packet_sniffer.py --count 10 --protocol UDP
```

### ICMP

ICMP traffic can be filtered using:

```bash
python packet_sniffer.py --count 10 --protocol ICMP
```

For example, ICMP traffic can be generated using:

```bash
ping -n 10 8.8.8.8
```

## Port Filtering

Specific TCP or UDP ports can also be monitored.

For example, to analyse HTTPS traffic:

```bash
python packet_sniffer.py --count 10 --port 443
```

DNS traffic can be monitored using:

```bash
python packet_sniffer.py --count 10 --port 53
```

Protocol and port filters can also be combined:

```bash
python packet_sniffer.py --count 20 --protocol TCP --port 443
```

This allows the analyser to focus specifically on TCP traffic using port 443.

## Service Identification

The analyser provides basic service identification by mapping commonly used network ports to their associated services.

| Port | Service | Port | Service |
|---:|---|---:|---|
| 21 | FTP | 110 | POP3 |
| 22 | SSH | 123 | NTP |
| 23 | TELNET | 143 | IMAP |
| 25 | SMTP | 161 | SNMP |
| 53 | DNS | 389 | LDAP |
| 67 | DHCP | 443 | HTTPS |
| 68 | DHCP | 445 | SMB |
| 80 | HTTP | 3389 | RDP |

For example, traffic using destination port `443` will be identified as HTTPS:

```text
TCP    192.0.2.10      -> 203.0.113.20    54321  -> 443    -        -> HTTPS    66 bytes
```

The service identification is based on commonly associated port numbers rather than deep inspection of the application protocol.

## Packet Size Analysis

The analyser also records the size of each captured packet and calculates:

- Total data captured
- Average packet size
- Largest packet
- Smallest packet

Example:

```text
Packet size statistics:

Total data captured : 18432 bytes
Average packet size : 921.60 bytes
Largest packet      : 1514 bytes
Smallest packet     : 54 bytes
```

## Exporting Reports

Captured traffic can be exported to a text report using the `--output` argument.

For example:

```bash
python packet_sniffer.py --count 20 --output report.txt
```

The generated report contains both the individual packet records and the capture summary.

A report can also be created while applying filters:

```bash
python packet_sniffer.py --count 50 --protocol TCP --port 443 --output https_report.txt
```

## Command-Line Options

| Option | Description | Example |
|---|---|---|
| `--count` | Number of matching packets to analyse | `--count 20` |
| `--protocol` | Filter by TCP, UDP or ICMP | `--protocol TCP` |
| `--port` | Filter by a specific TCP/UDP port | `--port 443` |
| `--output` | Save results to a text report | `--output report.txt` |

Options can also be combined.

For example:

```bash
python packet_sniffer.py --count 50 --protocol TCP --port 443 --output https_report.txt
```

## Limitations

This is a relatively simple packet analysis tool and is not intended to replace more advanced tools such as Wireshark.

Currently, the analyser:

- Focuses on IPv4 traffic
- Uses common port numbers for basic service identification
- Does not decrypt encrypted traffic
- Does not perform packet injection or modification
- Does not attempt to capture credentials or other sensitive application data
- Does not provide deep protocol analysis

## Future Improvements

Possible future improvements include:

- IPv6 support
- More detailed protocol analysis
- Improved service identification
- CSV or JSON report export
- Traffic visualisation
- More advanced statistical analysis
- Configurable capture interfaces
- Detection of unusual traffic patterns

## Disclaimer

This project is intended for **educational and authorised network monitoring purposes**.

Only capture and analyse network traffic on systems and networks where you have permission to do so.
