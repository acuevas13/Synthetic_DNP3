from scapy.all import *
from dnp3_dissector import *

pcapList = []
ackNum = -1
seqNum = -1

# pcapFile = "../B/siabmgrB2-1300-filtered.pcap"
# pcapFile = "../B/siabmgrB2-1600-filtered.pcap"
pcapFile = "../B/siabmgrB2-1800-filtered.pcap"


for p in PcapReader(pcapFile):
    # pktNumber += 1

    if TCP in p and p[TCP].seq == seqNum and p[TCP].ack == ackNum:
        continue
    
    if TransportControl in p:
        seqNum = p[TCP].seq
        ackNum = p[TCP].ack

        pcapList.append(p)
        
        
wrpcap("dtmc_siabmgrB2.pcap", pcapList)
