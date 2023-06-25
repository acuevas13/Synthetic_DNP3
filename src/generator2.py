from dnp3_dissector import *
from scapy.all import *
from cycleDetect import *

def getPacket(pcapFile, pktID):
    packet = None
    pktNum = 0
    for p in PcapReader(pcapFile):
        pktNum += 1
        # print(pktNum)
        if pktNum == pktID:
            if ApplicationLayer in p:
                packet = p
                # p.show()
                # return p
                break
    return packet

pcapList = []

pcapFile = "/data/netgen/B/siabmgrB2-1300-filtered.pcap"
# Read 1
read1 = getPacket(pcapFile, 8)
read2 = read1.copy()
pcapList.append(read1)
print(f"read1")
read1.show()
print()

# Response 1
response1 = getPacket(pcapFile, 10)
pcapList.append(response1)
print(f"response1")
response1.show()
print()

# Read 2
read2[IP].id = read1[IP].id + 1

lastLength = len(response1[DNP3]) + 2

ackTemp = response1[IP].ack
read2[IP].ack = response1[IP].seq + lastLength
read2[IP].seq = ackTemp

pcapList.append(read2)
print(f"read2")
read2.show()
print()

wrpcap("scada_traffic.pcap", pcapList)
