#!/usr/bin/env python3
import dpkt
import sys
import socket

def detect_syn_scan(pcap_file):
    # Dictionaries to store counts of SYN and SYN+ACK packets
    syn_packets = {}
    syn_ack_packets = {}

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for _, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data

                # Check for SYN flag without ACK flag
                if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
                    src_ip = socket.inet_ntoa(ip.src)
                    syn_packets[src_ip] = syn_packets.get(src_ip, 0) + 1

                # Check for both SYN and ACK flags
                elif tcp.flags & dpkt.tcp.TH_SYN and tcp.flags & dpkt.tcp.TH_ACK:
                    dst_ip = socket.inet_ntoa(ip.dst)
                    syn_ack_packets[dst_ip] = syn_ack_packets.get(dst_ip, 0) + 1

            except Exception as e:
                # Silently ignore malformed packets or packets not using Ethernet, IP, and TCP
                pass

    # Compare SYN vs. SYN+ACK counts and print suspicious IPs
    for ip, syn_count in syn_packets.items():
        syn_ack_count = syn_ack_packets.get(ip, 0)
        if syn_count > 3 * syn_ack_count:
            print(ip)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python detector.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file_path = sys.argv[1]
    detect_syn_scan(pcap_file_path)
