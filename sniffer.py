# Basic Network Sniffer (Task 1)
# Usage:
#   sudo python3 sniffer.py --interface eth0
#   python3 sniffer.py --read-pcap sample.pcap --count 10
#
# Requires: scapy
import argparse
import sys
from scapy.all import sniff, rdpcap, Packet, IP, TCP, UDP

def summarize_packet(pkt):
    layers = []
    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
    else:
        src = dst = proto = 'N/A'

    sport = dport = 'N/A'
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        l4 = 'TCP'
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        l4 = 'UDP'
    else:
        l4 = 'Other'

    summary = f"Src: {src}:{sport} -> Dst: {dst}:{dport} | L4: {l4} | Proto: {proto} | Len: {len(pkt)}"
    return summary

def print_pkt(pkt):
    try:
        print(summarize_packet(pkt))
        # print a short hex preview of payload
        raw = bytes(pkt.payload)
        if raw:
            preview = raw[:48]
            print('  Payload (hex preview):', preview.hex(), '...') if len(raw)>48 else print('  Payload (hex):', preview.hex())
    except Exception as e:
        print('Error parsing packet:', e)

def main():
    parser = argparse.ArgumentParser(description='Basic Network Sniffer - Task 1')
    parser.add_argument('--interface', '-i', help='Interface to sniff, e.g. eth0')
    parser.add_argument('--count', '-c', type=int, default=0, help='Number of packets to capture (0 for continuous)')
    parser.add_argument('--read-pcap', help='Read and analyze packets from a pcap file instead of live sniffing')
    parser.add_argument('--write-pcap', help='Write captured packets to a pcap file')
    args = parser.parse_args()

    if args.read_pcap:
        print('Reading pcap:', args.read_pcap)
        pkts = rdpcap(args.read_pcap)
        for i, p in enumerate(pkts):
            print(f"[{i+1}] {summarize_packet(p)}")
        return

    if not args.interface:
        print('Please specify an interface with --interface when live sniffing. Use --read-pcap to analyze a pcap file.')
        sys.exit(1)

    print(f"Starting live capture on interface {args.interface} (count={args.count})")
    try:
        pkts = sniff(iface=args.interface, prn=print_pkt, count=args.count or None, store=bool(args.write_pcap))
    except PermissionError:
        print('Permission denied: live sniffing usually requires root privileges. Try running with sudo.')
        sys.exit(1)
    except Exception as e:
        print('Error during sniffing:', e)
        sys.exit(1)

    if args.write_pcap:
        from scapy.utils import wrpcap
        wrpcap(args.write_pcap, pkts)
        print('Wrote pcap to', args.write_pcap)

if __name__ == '__main__':
    main()
