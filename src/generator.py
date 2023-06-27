import random
from statistics import mean
from dnp3_dissector import *
from scapy.all import *
from cycleDetect import *

DNP3_START = 1380
DNP3_PORT_NUMBER = 20000
TTL_DEFAULT = 64
TCP_HEADER_LEN = 8

appFuncCodes = {
    "confirm": 0,
    "read": 1,
    "write": 2,
    "select": 3,
    "operate": 4,
    "dir_operate": 5,
    "response": 129,
}

prmFuncCodes = {
    "reset_link_states": 0,
    "test_link_states": 2,
    "confirmed_user_data": 3,
    "unconfirmed_user_data": 4,
    "request_link_status": 9,
}


def getPacket(pcapFile, pktID):
    packet = None
    pktNum = 0
    for p in PcapReader(pcapFile):
        pktNum += 1
        if pktNum == pktID:
            if ApplicationLayer in p:
                packet = p
                break
    return packet


def create_DNP3_packet(src_mac, dst_mac, src_IP, dst_IP, IP_ID, sport, dport, tValue, tEcho, seq_TCP, ack_TCP, src_dnp3, dst_dnp3, funcCode, funcCode_PRM, transSeq, confirm_flag, appSeq):
    # Init Settings
    flags_IP = 'DF'
    flags_TCP = 'PA'
    direction_DL_BIT = 1
    primary_DL_BIT = 1

    if funcCode and funcCode == 1:
        flags_IP = 'DF'
        flags_TCP = 'PA'
        direction_DL_BIT = 1
        primary_DL_BIT = 1
    elif funcCode and funcCode == 129:
        flags_IP = ''
        flags_TCP = 'PA'
        direction_DL_BIT = 0
        primary_DL_BIT = 1
    elif funcCode and funcCode == 0:
        flags_IP = 'DF'
        flags_TCP = 'PA'
        direction_DL_BIT = 1
        primary_DL_BIT = 1

    if funcCode_PRM == 9:
        flags_IP = 'DF'
        flags_TCP = 'PA'
        direction_DL_BIT = 1
        primary_DL_BIT = 1
        
    elif funcCode_PRM == 11:
        flags_IP = ''
        flags_TCP = 'PA'
        direction_DL_BIT = 0
        primary_DL_BIT = 0
        
    # DNP3
    dataLinkControl = DataLinkLayerControl(DIR=direction_DL_BIT, PRM=primary_DL_BIT, funcation_code_primary=funcCode_PRM)

    dnp3_layer = DNP3(start=DNP3_START, control=dataLinkControl, destination=dst_dnp3, source=src_dnp3)
    
    transport_layer = TransportControl(final=1, first=1, sequence=transSeq)
    
    appControl = ApplicationControl(final=1, first=1, confirm=confirm_flag, unsolicited=0, sequence=appSeq)
    
    application_layer = None
    appRequest_layer = None
    if funcCode and funcCode == 1:
        qualiferField = DataObjectQualifer(reserved=0, PrefixCode=0, RangeCode=6)
        appRequest_layer = ApplicationRequest(Object0=60,
                                              Var0=2,
                                              QualiferField0=qualiferField,
                                              Object1=60,
                                              Var1=3,
                                              QualiferField1=qualiferField,
                                              Object2=60,
                                              Var2=4,
                                              QualiferField2=qualiferField)
        application_layer = ApplicationLayer(Application_Control=appControl, Function_Code=funcCode) / appRequest_layer

    elif funcCode and funcCode == 129:
        application_layer = ApplicationLayer(Application_Control=appControl, 
                                             Function_Code=funcCode, 
                                             Internal_Indications=ApplicationInternalIndications())

    # TCP
    tcpOptions = [('NOP', None), ('NOP', None), ('Timestamp', (tValue, tEcho))]
    tcp_layer = TCP(sport=sport, dport=dport, seq=seq_TCP, ack=ack_TCP, dataofs=TCP_HEADER_LEN, flags=flags_TCP, options=tcpOptions)
    
    # IP
    ip_layer = IP(id=IP_ID, flags=flags_IP, ttl=TTL_DEFAULT, src=src_IP, dst=dst_IP)
    
    # Ether
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    
    # Assemble Packet
    packet = ether_layer / ip_layer/ tcp_layer / dnp3_layer / transport_layer / application_layer
   
    packet.show()
    return packet

def generate_timestamps(avg_period, min_period, max_period, std_dev, num_messages):
    timestamps = []
    periods = []
    current_time = 0

    for _ in range(num_messages):
        # Calculate the duration for the next message based on a normal distribution
        duration = random.gauss(avg_period, std_dev)

        # Ensure the duration is within the specified min and max values
        # duration = max(min_period, min(max_period, duration))
        periods.append(duration)
        
        # Add the duration to the current time
        current_time += duration
        timestamps.append(current_time)
    return timestamps

if __name__ == '__main__':
    pcapFile = "/data/netgen/B/siabmgrB2-1300-filtered.pcap"
    
    # Get tokenized flows of pcap
    t1 = time.time()
    tokenized = multiTokenizer(pcapFile)
    print(f"Tokenize Time: {time.time()-t1}")
    
    # Test 0
    # key = ('172.28.2.10', 1389, '172.28.2.20', 20000)
    # val = [(1572267718.936242, 8, 'read123', 0), (1572267724.925966, 41, 'read123', 7), (1572267724.941265, 45, 'confirm', 8), (1572267730.925625, 75, 'read0123', 14), (1572267731.941265, 80, 'confirm', 80),
    #        (1572267732.925625, 100, 'read0123', 100), (1572267730.925301, 103, 'read123', 20), (1572267735.925044, 131, 'read123', 26), (1572267741.924758, 153, 'read123', 31), (1572267754.924484, 175, 'read0123', 36)]
    # tokenized = {key: val}
    
    # # Test 1 - 1300
    key = ('172.28.2.10', 1389, '172.28.2.20', 20000)
    val = tokenized[key]
    tokenized = {key: val}
    
    t1 = time.time()
    for flow, tokenized_flow in tokenized.items():
        N = 2
        epsilon = 1
        dur_thr = 1
        print(f"----------------============= Flow: {flow} =============----------------")
        result = find_periodic_requests(tokenized_flow, N, epsilon, dur_thr)
    print(f"Learner Time: {time.time()-t1}")
    
    
    # Add messages timesta
    timeStamps = []
    for flow in info:
        