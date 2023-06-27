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


def getRequestType(pkt):    
    if ApplicationRequest in pkt:
        requestID = ""
        for i in range(4):
            obj = pkt[ApplicationRequest].getfieldval("Object" + str(i))
            var = pkt[ApplicationRequest].getfieldval("Var" + str(i))
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
                    token = (float(p.time), msgID, msgType, pairID)
                    tokenized_longLived_flows[tup].append(token)
                    
                    unPairedDSTs[tup2] = (tup, pairID)
                    pairID += 1
            else:
                # Response
                if msgType == "response":
                    (tup2, pastPairID) = unPairedDSTs[tup]
                    token = (float(p.time), msgID, msgType, pastPairID)
                    tokenized_longLived_flows[tup].append(token)
                    del unPairedDSTs[tup]
                else:
                    print(f"Ignored Function Code: {msgType}")

    print(f"unsolicitedResponses: {unsolicitedResponses}")
    return tokenized_longLived_flows


# 3.) Learner:
# Input: A tokenized flow and parameters N; ε; dur_thr
# Output: A list of tuples (request set, dur_min; dur_max; dur_std)

# Input: N_identical_cycles - List of at least N identical candiates cycle. Each candiate cycle is a list
def getCandidateDurations(lst_N_identical_candidates, pktsInGroup):
    lst_stats = []
    for n_ident_candiates in lst_N_identical_candidates:
        all_durations = []
        for i in range(1, len(n_ident_candiates)):
            idx1, idx2 = n_ident_candiates[i - 1][0], n_ident_candiates[i][0]
            t1, t2 = pktsInGroup[idx1][0], pktsInGroup[idx2][0]
            duration = t2 - t1
            all_durations.append(duration)
            
        min_dur, max_dur, std_dur = min(all_durations), max(all_durations), -1
        if len(all_durations) >= 2:
            std_dur = statistics.stdev(all_durations)
        
        print(f"all_durations: {all_durations}")
        print(
            f"min: {min_dur}, max: {max_dur}, std: {std_dur}, avg: {statistics.mean(all_durations)}\n")
        lst_stats.append((min_dur, max_dur, std_dur, n_ident_candiates))
    
    return lst_stats



def find_candidate_cycles(pktsInGroup, N, dur_thr):
    candidate_cycles = []
    current_cycle = []
    print(f"pktsInGroup: {pktsInGroup}")
    
    # Find canidate cycles, each with unique msgs 
    for i, pkt in enumerate(pktsInGroup):
        msgType = pkt[2]
        
        if not current_cycle:
            current_cycle.append((msgType, i))
            continue

        for tup in current_cycle:
            if msgType in tup:
                candidate_cycles.append(current_cycle)
                current_cycle = []
                break
            
        current_cycle.append((msgType, i))

    if current_cycle:
        candidate_cycles.append(current_cycle)
        
    print(f"candidate_cycles: {candidate_cycles}")
    
    # Continue search until candidate_cycles w/ N identical
    # for subset in itertools.combinations(group, len(group)):
    groups = {}
    for lst in candidate_cycles:
        indexes = []
        key = ""
        for msg in lst:
            key += msg[0]
            indexes.append(msg[1])         

        key = ''.join(sorted(key))

        if key not in groups:
            groups[key] = []
        groups[key].append(indexes)

    N_identical_candidates = [lst for lst in groups.values() if len(lst) >= N]
    print(f"N_identical_candidates: {N_identical_candidates}")
    
    # Verify Timing
    lst_stats = getCandidateDurations(N_identical_candidates, pktsInGroup)
    # result = []
    # for s in lst_stats:
    #     min_dur, max_dur = s[0], s[1]
    #     if max_dur - min_dur < dur_thr:
    #         result.append(s)

    return lst_stats

def find_periodic_requests(tokenized_flow, N, epsilon, dur_thr):
    request_occurrences = {}
    non_periodic = []
    
    # Find frequency of each msg type
    for pkt in tokenized_flow:
        msgType = pkt[2]
        if not msgType:
            msgType = "None"
        if msgType in request_occurrences:
            request_occurrences[msgType] += 1
        else:
            request_occurrences[msgType] = 1
    print(f"request_occurrences: {request_occurrences}\n")

    result = []
    for counter in request_occurrences.values():
        # Group by msg types that are within epilon frequency
        group = [request for request, count in request_occurrences.items() if count >= counter - epsilon and count <= counter + epsilon]
        print(f"group: {group}")
        
        # Filter by pkts that are in group 
        pktsInGroup = [pkt for pkt in tokenized_flow if pkt[2] in group]
        
        # Find candiate cycles with no duplicates
        verifed_cycles = find_candidate_cycles(pktsInGroup, N, dur_thr)
     
        # Declare non-eligible pkts as non-periodic
        if not verifed_cycles:
            non_periodic.append(pktsInGroup)
        
        result.append(verifed_cycles)
               
    print(f"result: {result}")
    print()
    return result

    
if __name__ == '__main__':
    pcapFile = "/data/netgen/B/siabmgrB2-1300-filtered.pcap"
    # pcapFile = "/data/netgen/siabmgrA5/siabmgrA5-20191030-174849.pcap"
    # pcapFile = "../B/siabmgrB2-1300-filtered.pcap"
    # pcapFile = "../B/siabmgrA5-20191030-174849.pcap"
    t1 = time.time()
    tokenized = multiTokenizer(pcapFile)
    print(f"Tokenize Time: {time.time()-t1}")
    
    # Test 0
    # key = ('172.28.2.10', 1389, '172.28.2.20', 20000)
    # val = [(1572267718.936242, 8, 'read123', 0), (1572267724.925966, 41, 'read123', 7), (1572267724.941265, 45, 'confirm', 8), (1572267730.925625, 75, 'read0123', 14), (1572267731.941265, 80, 'confirm', 80),
    #        (1572267732.925625, 100, 'read0123', 100), (1572267730.925301, 103, 'read123', 20), (1572267735.925044, 131, 'read123', 26), (1572267741.924758, 153, 'read123', 31), (1572267754.924484, 175, 'read0123', 36)]
    # tokenized = {key: val}
    
    # Test 1 - 1300
    # key = ('172.28.2.10', 1389, '172.28.2.20', 20000)
    # val = tokenized[key]
    # tokenized = {key: val} 
    
    # Test 2 - A5_1030
    # key = ('172.27.5.11', 47292, '172.27.5.23', 20000)
    # val = tokenized[key]
    # tokenized = {key: val}

    t1 = time.time()
    for flow, tokenized_flow in tokenized.items():
        N = 2
        epsilon = 1
        dur_thr = 1
        print(f"----------------============= Flow: {flow} =============----------------")
        find_periodic_requests(tokenized_flow, N, epsilon, dur_thr)
        # print(f"Flow: {flow}, len: {len(listOfTokens)}")
        # for t in listOfTokens:
        #     print(f"    ts: {t[0]}, msgID: {t[1]}, pairID: {t[2]}")
        # print()
    print(f"Learner Time: {time.time()-t1}")
