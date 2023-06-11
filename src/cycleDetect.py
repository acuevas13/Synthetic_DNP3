import statistics
import itertools
from dnp3_dissector import *
from scapy.all import *
import sys
import time
import csv

# Class Data Objects
classDataObjectCodes = {
   (60, 1) : "0",
   (60, 2): "1",
   (60, 3): "2",
   (60, 4): "3",
}

applicationFunctCodes = {
    0: "confirm",
    1: "read",
    2: "write",
    3: "select",
    4: "operate",
    5: "dir_operate",
    6: "dir_operate_no_resp",
    7: "freeze",
    8: "freeze_no_resp",
    9: "freeze_clear",
    10: "freeze_clear_no_resp",
    11: "freeze_at_time",
    12: "freeze_at_time_no_resp",
    13: "cold_restart",
    14: "warm_restart",
    15: "initialize_data",
    16: "initialize_application",
    17: "start_application",
    18: "stop_application",
    19: "save_configuration",
    20: "enable_unsolicited",
    21: "disable_unsolicited",
    22: "assign_class",
    23: "delay_measurement",
    24: "record_current_time",
    25: "open_file",
    26: "close_file",
    27: "delete_file",
    28: "get_file_information",
    29: "authenticate_file",
    30: "abort_file",
    129: "response",
    130: "unsolicited_resp",
}



def getRequestType(p):    
    if ApplicationRequest in p:
        requestID = ""
        for i in range(4):
            obj = p[ApplicationRequest].getfieldval("Object" + str(i))
            var = p[ApplicationRequest].getfieldval("Var" + str(i))
            if obj and var:
                requestID += classDataObjectCodes[(obj, var)]
        return ''.join(sorted(requestID))

    

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
            # p.show()
            # print(f"pkt: {pktNumber}")
            tup = (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
            tup2 = (p[IP].dst, p[TCP].dport, p[IP].src, p[TCP].sport)
            msgType = applicationFunctCodes[p[ApplicationLayer].Function_Code]
            msgID = pktNumber
            
            if tup not in tokenized_longLived_flows:
                # print(f"src: {p[IP].src}:{p[TCP].sport}, dst: {p[IP].dst}:{p[TCP].dport}")
                tokenized_longLived_flows[tup] = []

            if tup not in unPairedDSTs:
                # Unsolicited Response
                if msgType == "response":
                    unsolicitedResponses.append(pktNumber)
                # Request/Confirm/Etc 
                else:
                    if msgType == "read":
                        msgType += getRequestType(p)
                    token = (p.time, msgID, msgType, pairID)
                    tokenized_longLived_flows[tup].append(token)
                    
                    unPairedDSTs[tup2] = (tup, pairID)
                    pairID += 1
            else:
                # Response
                if msgType == "response":
                    (tup2, pastPairID) = unPairedDSTs[tup]
                    token = (p.time, msgID, msgType, pastPairID)
                    tokenized_longLived_flows[tup].append(token)
                    del unPairedDSTs[tup]
                else:
                    print(f"Ignored Function Code: {msgType}")

    print(f"unsolicitedResponses: {unsolicitedResponses}")
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


def find_periodic_requests(tokenized_flow, N, epsilon, dur_thr):
    request_occurrences = {}
    for pkt in tokenized_flow:
        msgType = pkt[2]
        if not msgType:
            msgType = "None"
        if msgType in request_occurrences:
            request_occurrences[msgType] += 1
        else:
            request_occurrences[msgType] = 1
    print(f"request_occurrences: {request_occurrences}\n")

    # result = []
    # for counter in request_occurrences.values():
    #     group = [request for request, count in request_occurrences.items() if count >= counter - epsilon and count <= counter + epsilon]
    #     for subset in itertools.combinations(group, counter):
    #         candidates = []
    #         for request in subset:
    #             candidates.extend([request] * N)

    #         dur_min = min(candidates)
    #         dur_max = max(candidates)
    #         if dur_max - dur_min < dur_thr:
    #             dur_std = statistics.stdev(candidates)
    #             result.append((subset, dur_min, dur_max, dur_std))
    #             continue

    # return result

    
if __name__ == '__main__':
    # pcapFile = "/data/netgen/B/testB2-1300-filtered.pcap"
    # pcapFile = "/data/netgen/siabmgrA5/siabmgrA5-20191030-174849.pcap"

    pcapFile = "../B/siabmgrB2-1300-filtered.pcap"
    # pcapFile = "../B/siabmgrA5-20191030-174849.pcap"
    tokenized = multiTokenizer(pcapFile)
    for flow, tokenized_flow in tokenized.items():
        N = 2
        epsilon = 1
        dur_thr = 1
        print(f"Flow: {flow}")
        find_periodic_requests(tokenized_flow, N, epsilon, dur_thr)
        # print(f"Flow: {flow}, len: {len(listOfTokens)}")
        # for t in listOfTokens:
        #     print(f"    ts: {t[0]}, msgID: {t[1]}, pairID: {t[2]}")
        # print()
