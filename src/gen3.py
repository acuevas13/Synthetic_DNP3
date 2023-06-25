from dnp3_dissector import *
from scapy.all import *
from cycleDetect import *

DNP3_START = 1380
DNP3_PORT_NUMBER = 20000  # Set the DNP3 port number used in your packets
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
        # print(pktNum)
        if pktNum == pktID:
            if ApplicationLayer in p:
                packet = p
                # p.show()
                # return p
                break
    return packet


def create_DNP3_packet(src_mac, dst_mac, src_IP, dst_IP, IP_ID, sport, dport, tValue, tEcho, seq_TCP, ack_TCP, src_dnp3, dst_dnp3, funcCode, funcCode_PRM, transSeq, confirm_flag, appSeq):
    # pcapFile = "../B/siabmgrB2-1300-filtered.pcap"
    pcapFile = "/data/netgen/B/siabmgrB2-1300-filtered.pcap"
    
    # ptest = getPacket(pcapFile, 8)
    # ptest.show()
    
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

    dnp3_layer = DNP3(start=DNP3_START, length=17, control=dataLinkControl, destination=dst_dnp3, source=src_dnp3)
    
    transport_layer = TransportControl(final=1, first=1, sequence=transSeq)
    
    appControl = ApplicationControl(final=1, first=1, confirm=confirm_flag, unsolicited=0, sequence=appSeq)
    application_layer = ApplicationLayer(Application_Control=appControl, Function_Code=funcCode)
    
    qualiferField = DataObjectQualifer(reserved=0, PrefixCode=0, RangeCode=6)
    applicationRequest_layer = ApplicationRequest(Object0=60, Var0=2, QualiferField0=qualiferField, Object1=60, Var1=3, QualiferField1=qualiferField, Object2=60, Var2=4, QualiferField2=qualiferField)
    
    # TCP
    tcpOptions = [('NOP', None), ('NOP', None), ('Timestamp', (tValue, tEcho))]
    tcp_layer = TCP(sport=sport, dport=dport, seq=seq_TCP, ack=ack_TCP, dataofs=TCP_HEADER_LEN, flags=flags_TCP, options=tcpOptions)
    
    # IP
    ip_layer = IP(id=IP_ID, flags=flags_IP, ttl=TTL_DEFAULT, src=src_IP, dst=dst_IP)
    
    # Ether
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    
    # Assemble Packet
    packet = ether_layer / ip_layer/ tcp_layer / dnp3_layer / transport_layer / application_layer / applicationRequest_layer
   
    packet.show()
    return packet


RTU_mac = '00:20:75:20:d2:fa'
RTU_IP = "172.28.2.10"
RTU_PORT = 1389
RTU_DNP3_ADDR = 1

RELAY_IP = "172.28.2.20"
RELAY_mac = '00:90:4f:e5:38:a1'
RELAY_PORT = 20000
RELAY_DNP3_ADDR = 1

start_IP_ID = 61353
CURR_IP_ID = start_IP_ID

read1_tvalue = 351402
read1_techo = 175674600

startSeq_TCP = 2216652531
currSeq_TCP = startSeq_TCP
startAck_TCP = 3242157396
currACK_TCP = startAck_TCP

startTransportControlSeq_DNP3 = 50
currTransSeq_DNP3 = startTransportControlSeq_DNP3

startAppSeq = 5
currAppSeq = startAppSeq

# Read 1 (pkt:8,1300)
read1 = create_DNP3_packet(src_mac=RTU_mac,
                           dst_mac=RELAY_mac,
                           src_IP=RTU_IP,
                           dst_IP=RELAY_IP,
                           IP_ID=CURR_IP_ID,
                           sport=RTU_PORT,
                           dport=RELAY_PORT,
                           tValue=read1_tvalue,
                           tEcho=read1_techo,
                           seq_TCP=currSeq_TCP,
                           ack_TCP= currACK_TCP,
                           src_dnp3=RTU_DNP3_ADDR,
                           dst_dnp3=RELAY_DNP3_ADDR,
                           funcCode=appFuncCodes["read"],
                           funcCode_PRM=prmFuncCodes["unconfirmed_user_data"],
                           transSeq=currTransSeq_DNP3,
                           confirm_flag=0,
                           appSeq=currAppSeq)
    

pcapList = []
pcapList.append(read1)
wrpcap("scada_traffic.pcap", pcapList)
