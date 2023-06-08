from dnp3_dissector import *
from scapy.all import *
import sys
import time
import csv

# 1.) Multiplexer: 
# Input:  (.pcap) file
# Output: (set) shortLived_flows  - Connections (< 1 sec) grouped by (IP Protocol, Server Port, Client Address) 
#         (set) longLived_flows - Connections grouped by (IP Protocol, Server Port, Client Address, Client Port)
# 2.) Tokenizer: 
# Input:  (.pcap) file 
#         (list) shortLived_flows and longLived_flows
# Output: (dict) tokenized_shortLived_flows - [Key]: (tuple) Flow, [Value]: (list of tuple) List of tokenized packets in this flow
#         (dict) tokenized_longLived_flows - [Key]: (tuple) Flow, [Value]: (list of tuple) List of tokenized packets in this flow
#             Request:
#                Tuple - (timestamp, messageIdentifier, pairIdentifier)
#             Response: 
#                Tuple - (timestamp, pairIdentifier)
def multiTokenizer(pcapFile):
    # shortLived_flows = set()
    # longLived_flows = set()
    unPairedDSTs = {}
    pairID = 0
    tokenized_longLived_flows = {}
    unsolicitedResponses = []
    pktNumber = 0
    
    for p in PcapReader(pcapFile):
        pktNumber += 1
        if ApplicationLayer in p:
            print(f"pkt: {pktNumber}")
            tup = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
            tup2 = (p[IP].dst, p[TCP].dport, p[IP].src, p[TCP].sport)
            
            if tup not in tokenized_longLived_flows:
                print(f"src: {p[IP].src}:{p[TCP].sport}, dst: {p[IP].dst}:{p[TCP].dport}")
                tokenized_longLived_flows[tup] = []

            if tup not in unPairedDSTs:
                # Unsolicited Response
                if p[ApplicationLayer].Function_Code == 129:
                    unsolicitedResponses.append(pktNumber)
                # Request
                else:
                    msgID = pktNumber
                    token = (p.time, msgID, pairID)
                    tokenized_longLived_flows[tup].append(token)
                    
                    unPairedDSTs[tup2] = (tup, pairID)
                    pairID += 1
            else:
                # Response
                if p[ApplicationLayer].Function_Code == 129:
                    msgID = pktNumber
                    (tup2, pastPairID) = unPairedDSTs[tup]
                    token = (p.time, msgID, pastPairID)
                    tokenized_longLived_flows[tup].append(token)
                    del unPairedDSTs[tup]
                else:
                    print(f"Ignored Function Code: {p[ApplicationLayer].Function_Code}")

    print(f"unsolicitedResponses: {unsolicitedResponses}")
    return tokenized_longLived_flows


if __name__ == '__main__':
    # pcapFile = "/data/netgen/B/testB2-1300-filtered.pcap"
    # pcapFile = "/data/netgen/siabmgrA5/siabmgrA5-20191030-174849.pcap"

    pcapFile = "../B/siabmgrB2-1300-filtered.pcap"
    # pcapFile = "../B/siabmgrA5-20191030-174849.pcap"
    tokenized = multiTokenizer(pcapFile)
    for flow, listOfTokens in tokenized.items():
        print(f"Flow: {flow}, len: {len(listOfTokens)}")
        for t in listOfTokens:
            print(f"    ts: {t[0]}, msgID: {t[1]}, pairID: {t[2]}")
        print()
