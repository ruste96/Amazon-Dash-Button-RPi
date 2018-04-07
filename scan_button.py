# Import scapy Lib
from scapy.all import *

# Arping interface
IFACE = "wlan0"

# Check button function
def scan_arp(pkt):
    if pkt.haslayer(ARP):
        print("[NEW ARP Result] From:\nIP: {0}\nMAC: {1}\n".format(pkt[ARP].psrc, pkt[ARP].hwsrc))

# Start sniffing
print("Start sniffing (CTRL+C stop)")
pkts = sniff(iface=IFACE, filter="arp", count=0, store=0, prn=scan_arp)
print(pkts.summary())
