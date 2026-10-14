# My DPI Packet Analyzer

## About
A Python-based packet analysis project that reads saved PCAP capture files and displays packet information.

## Features
- Read PCAP and PCAPNG capture files
- Display source and destination IPv4 addresses
- Display TCP and UDP ports
- Classify likely HTTP, HTTPS, and DNS traffic using port numbers
- Show packet sizes and protocol statistics
- Export IPv4 packet details to a CSV report
- Preview available readable payload text

## Requirements
- Python
- Scapy

## Installation
Install Scapy with:

    py -m pip install scapy

## How to Run
1. Place a PCAP file in the project folder.
2. Open the project folder in VS Code.
3. Open the terminal.
4. Run:

       py main.py

5. Enter the PCAP filename when prompted.

## Limitations
Service labels are inferred from port numbers and may not identify every application correctly. HTTPS payloads remain encrypted. Inspect only traffic you are authorized to analyze.


This version includes my own modifications and learning exercises.