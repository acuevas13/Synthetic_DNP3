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
#                Tuple - (timestamp, messageIdentifier, pathIdentifier)
#             Response: 
#                Tuple - (timestamp, pathIdentifier)
def multiTokenizer(pcapFile):
    # shortLived_flows = set()
    # longLived_flows = set()
    pairMap = {}
    pairID = 0
    tokenized_longLived_flows = {}
    pktNumber = 0
    
    for p in PcapReader(pcapFile):
        pktNumber += 1
        if ApplicationLayer in p:
            print(f"pkt: {pktNumber}")
            tup = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
            
            if tup not in pairMap:
                tup2  = (p[IP].dst, p[TCP].dport, p[IP].src, p[TCP].sport)
                pairMap[tup] = pairID
                pairMap[tup2] = pairID
                pairID += 1
            
            if tup not in tokenized_longLived_flows:
                print(f"src: {p[IP].src}:{p[TCP].sport}, dst: {p[IP].dst}:{p[TCP].dport}")
                
                tokenized_longLived_flows[tup] = []
            else:
                # Response
                if p[ApplicationLayer].Function_Code == 129:
                    currPairID = pairMap[tup]
                    token = (currPairID)
                # Resquest 
                elif p[ApplicationLayer].Function_Code == 1:
                    msgID = pktNumber
                    currPairID = pairMap[tup]
                    token = (msgID, currPairID)
                else:
                    continue
                tokenized_longLived_flows[tup].append((p.time, token))

                tokenized_longLived_flows[tup]
                
    return tokenized_longLived_flows


# 3.) Learner:
# Input: A tokenized flow and parameters N; ε; dur_thr
# Output: A list of tuples (request set, dur_min; dur_max; dur_std)
# Step 1: group requests
# count request occurrences;
#     group requests with same counter  + or - ε;
#     for each group do
#         for each subset in group do
#             # Step 2: find candidates n/
#             for each request in subset do
#                 candidates’N repeating cycles;
#                 # Step 3: test candidates n/
#                 dur_min; dur_max <- minimum and maximum candidate durations;
#                 if dur_max - dur_min < dur_thr
#                     dur_std <- cycle duration standard deviation;
#                     store (request set, dur_min; dur_max; dur_std);
#                     continue to next subset;
#                 else
#                     reset candidates;
#             end
#             ignore remaining subset requests as non-periodic;
#     end
# end

if __name__ == '__main__':
    pcapFile = "/data/netgen/B/testB2-1300-filtered.pcap"
    # pcapFile = "/data/netgen/siabmgrA5/siabmgrA5-20191030-174849.pcap"

    tokenized = multiTokenizer(pcapFile)
    for flow, listOfTokens in tokenized.items():
        print(f"Flow: {flow}, len: {len(listOfTokens)}")
        for t in listOfTokens:
            print (f"    timeStamp: {t[0]}, token: {t[1]}")
        print()