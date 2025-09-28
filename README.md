Task 1 - Basic Network Sniffer
------------------------------
This Python script uses scapy for packet capture and simple analysis.
It supports:
- Live sniffing from a network interface (requires root)
- Reading packets from a pcap file for offline analysis
- Optional writing of captured packets to a pcap file
Example:
    sudo python3 sniffer.py --interface eth0 --count 50 --write-pcap capture.pcap
