import numpy as np
from dnp3_dissector import *
from scapy.all import *
import statistics

"""
Algo:
1.) Find intra-relay timing distro (avg, std) (random.gauss(avg_period, std_dev))
    Find cycles
    - m1->m2 (different msgs)
    - kmeans cluster them
    - cluster is represented with starting msg pkt number
2.) Find inter-relay (per/flow) timing
    Find cycles
    - m1->m2 (different msgs)
    - kmeans cluster them
    - cluster is represented with starting msg pkt number
        a.) Find inter-cycle timing
            - Find distro on each msg in cycle (simplifed)
        b.) Which cycle to send?
            Find this frequency in data
            - Read, Response
            - Read, Response, Confirm
            - select, operate (manual event???? inster???)
            - link1,link2
        
3.) Round-robin generate timestampe representation:
    a.) Cycle in order (20, 30, 40 ,50) based on intra-relay (avg_period, std_period)
    b.) Inside relay:
        1.) Choice which cycle-for-this-flow based on this flows distro  (cycles_freq)
        2.) Add in cycle packets based on inter-cycle timing (inter_timing)
        
In summary:
intra_relay = avg, std
flows = {
            (10,20): {
                    "cycles": [(read123, resp), (read0123, resp), (read123, resp, confirm)],
                    "cycle_freq":   [(c1_avg, c1_std), (), ()],
                    "inter_timing":  [(c1_inter_avg, c1_inter_std), (), ()] #simplified
                    }
        } 

"""
# Class Data Objects
classDataObjectCodes = {
    (60, 1): "0",
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

# def kmeans(data, k, max_iter=100):
#     # Randomly initialize centroids
#     centroids = data[np.random.choice(len(data), size=k, replace=False)]

#     for _ in range(max_iter):
#         # Assign each data point to the closest centroid
#         labels = np.argmin(np.abs(data[:, None] - centroids), axis=1)

#         # Compute new centroids as the mean of the data points in each cluster
#         new_centroids = np.array([data[labels == i].mean() for i in range(k)])

#         # If centroids don't change, we're done
#         if np.all(centroids == new_centroids):
#             break

#         centroids = new_centroids

#     return labels, centroids

# def testKMeans():
#     data = np.array([0.1, 6.7, 0.2, 6.8, 0.1, 6.9, 5.0, 4.7, 4, 3, 7, 5, 0.2, 6.7])

#     labels, centroids = kmeans(data, k=2)

#     print(labels)


# def calculate_wcss(data):
#     wcss = []
#     for n in range(2, 21):
#         kmeans = KMeans(n_clusters=n)
#         kmeans.fit(X=data)
#         wcss.append(kmeans.inertia_)

#     return wcss


# def optimal_number_of_clusters(wcss):
#     x1, y1 = 2, wcss[0]
#     x2, y2 = 20, wcss[len(wcss)-1]

#     distances = []
#     for i in range(len(wcss)):
#         x0 = i+2
#         y0 = wcss[i]
#         numerator = abs((y2-y1)*x0 - (x2-x1)*y0 + x2*y1 - y2*x1)
#         denominator = np.sqrt((y2 - y1)**2 + (x2 - x1)**2)
#         distances.append(numerator/denominator)

#     return distances.index(max(distances)) + 2

# def test_kMeans():
#     # assuming your data is a list of integers
#     data = np.array([0.1, 6.7, 0.2, 6.8, 0.1, 6.9, 0.2, 6.7]).reshape(-1, 1)

#     # calculating the within clusters sum-of-squares for 19 cluster amounts
#     sum_of_squares = calculate_wcss(data)

#     # calculating the optimal number of clusters
#     n = optimal_number_of_clusters(sum_of_squares)
#     print(f'The optimal number of clusters is: {n}')
    
# Input: pcapFile, flows
# Output: flows
def find_cycle_info(pcapFile, flows, RTU, RELAYS):
    # Find cycles
    # - m1->m2 (different msgs)
    # - kmeans cluster them
    # - cluster is represented with starting msg pkt number
    VALID_MSG_TYPES = ["read123", "read0123", "response", "confirm"]
    lastMsg = {}
    for f in flows:
        lastMsg[f] = (-1, 0)
    
    pktID = 0
    for p in PcapReader(pcapFile):
        pktID += 1
        if ApplicationLayer in p:
            if p[IP].src not in RELAYS and p[IP].dst not in RELAYS:
                continue
            
            msgType = applicationFunctCodes[p[ApplicationLayer].Function_Code]
            
            if msgType == "read":
                msgType += getRequestType(p)
                
            if msgType not in VALID_MSG_TYPES:
                continue
            
            currRelay = ''
            if p[IP].src in RELAYS:
                currRelay = p[IP].src
            elif p[IP].dst in RELAYS:
                currRelay = p[IP].dst
            currFlow = (RTU, currRelay)
            
            lastPktId = lastMsg[currFlow][0]
            lastPktTime = lastMsg[currFlow][1]
            
            if lastPktId == -1:
                lastMsg[currFlow] = (pktID, p.time)
            else:
                print(f"currFlow: {currFlow}, pkt: {pktID}, lastMsg[currFlow]:{lastMsg[currFlow]}")
                timeGap = float(p.time - lastPktTime)
                newGap = (lastPktId, pktID, timeGap)
                flows[currFlow]["gaps"].append(newGap)
                lastMsg[currFlow] = (pktID, p.time)
                print(f"newGap: {newGap}, p.time: {p.time}. lastMsg[currFlow][1]: {lastMsg[currFlow][1]}")
    for f in flows:
        gaps = flows[f]["gaps"]
        print(f"f: {f}\n    gaps: {gaps}")
    return flows


def find_intra_relay_distro(pcapFile, RTU, RELAYS):
    periods = []
    lastMsg = ('', 0) # ip_addr, time
    pktID = 0
    for p in PcapReader(pcapFile): 
        pktID += 1
        if ApplicationLayer in p:
            if p[IP].src == RTU and p[IP].dst in RELAYS:
                if lastMsg[0] == '':
                    lastMsg = (p[IP].dst, p.time)
                    
                if p[IP].dst != lastMsg[0]:
                    print(f"pkt: {pktID}")
                    newPeriod = float(p.time - lastMsg[1])
                    periods.append(newPeriod)
                    lastMsg = (p[IP].dst, p.time)
                    print(f"newPeriod: {newPeriod}, p.time: {p.time}. lastMsg[1]: {lastMsg[1]}")
                    
    std_period = statistics.stdev(periods)
    avg_period = statistics.mean(periods)
    print(f"periods: {periods}")
    print(f"std_period: {std_period}")
    print(f"avg_period: {avg_period}")

    return avg_period, std_period

# Input: pcap file
# Output: timestamp represetnation of synthetic pcap
def cycle_detect():
    # 1.) Find intra-relay timing distro (avg, std) (random.gauss(avg_period, std_dev))
    pcapFile = "/data/netgen/B/siabmgrB2-1300-filtered.pcap"
    RTU = "172.28.2.10"
    RELAYS = ["172.28.2.20", "172.28.2.30", "172.28.2.40", "172.28.2.50"]
    # avg_period, std_period = find_intra_relay_distro(pcapFile, RTU, RELAYS)
    std_period= 0.865681433255568
    avg_period= 1.499332388078366
    
    # 2.) Find inter-relay (per/flow) timing
    flows = {}
    for relay in RELAYS:
        flows[(RTU, relay)] = {"gaps": [], "cycles": [], "cycle_freq": [], "inter_timing":[]}
        
    flows = find_cycle_info(pcapFile, flows, RTU, RELAYS)
    
    # 3.) Round-robin generate timestampe representation:
    timeStamps = []

    return timeStamps

cycle_detect()