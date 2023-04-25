from scapy.all import *
from scapy.layers.dnp3 import *

dnp3_pkt = DNP3(flags=0x01, dst=1, src=1024, control=3)
ether_pkt = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
pkt = ether_pkt / dnp3_pkt

wrpcap("output.pcap", [pkt])
