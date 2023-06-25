from dnp3_dissector import *
from scapy.all import *
from cycleDetect import *

DNP3_PORT_NUMBER = 20000  # Set the DNP3 port number used in your packets
TTL_DEFAULT = 64
TCP_HEADER_LEN = 8

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

def create_DNP3_packet(src_mac, dst_mac, src_IP, dst_IP, function_code, relay_status):
    # pcapFile = "../B/siabmgrB2-1300-filtered.pcap"
    pcapFile = "/data/netgen/B/siabmgrB2-1300-filtered.pcap"
    
    # packet = Ether()/IP()/TCP()/DNP3()
    ptest = getPacket(pcapFile, 8)
    ptest.show()
    
    # DNP3
    tempControl = DataLinkLayerControl()
    tempControl.DIR = 1
    tempControl.PRM = 1
    tempControl.FCB = 0
    tempControl.FCV = 0
    tempControl.funcation_code_primary = 4
    
    dnp3_layer = DNP3(start=1380, length=17, control=tempControl, destination=1, source=1) 
    transport_layer = TransportControl(final=1, first=1, sequence=50)
    tempAppControl = ApplicationControl()
    tempAppControl.final=1
    tempAppControl.first=1
    tempAppControl.confirm = 0
    tempAppControl.unsolicited = 0
    tempAppControl.sequence = 5
    application_layer = ApplicationLayer(Application_Control=tempAppControl, Function_Code=1)
    
    qualiferField = DataObjectQualifer(reserved=0, PrefixCode=0, RangeCode=6)
    applicationRequest_layer = ApplicationRequest(Object0=60, Var0=2, QualiferField0=qualiferField, Object1=60, Var1=3, QualiferField1=qualiferField, Object2=60, Var2=4, QualiferField2=qualiferField)
    # TCP
    currAck = 3242157396
    currSeq = 2216652531
    readOptions = [('NOP', None), ('NOP', None), ('Timestamp', (351402, 175674600))]

    tcp_layer = TCP(sport=1389, dport=20000, seq=currSeq, ack=currAck, dataofs=TCP_HEADER_LEN, flags='PA', options=readOptions)
    # IP
    currID = 61353
    ip_layer = IP(id=currID, flags='DF', ttl=TTL_DEFAULT, src=src_IP, dst=dst_IP)
    
    ether_layer = Ether(src=src_mac, dst=dst_mac)
    packet = ether_layer / ip_layer/ tcp_layer / dnp3_layer / transport_layer / application_layer / applicationRequest_layer
    
    # Pull Packet
    # del packet[TransportControl]
    # dnp3Save = packet[DNP3].copy()
    # del packet[DNP3]
    # tcpSave = packet[TCP].copy()
    # del packet[TCP]
    # ipSave = packet[IP].copy()
    # del packet[IP]
    # etherSave = packet[Ether].copy()
    # packet = Ether()/IP()/TCP()/DNP3()
    # packet[DNP3] = dnp3Save
    # packet[TCP] = tcpSave
    # packet[Ether] = etherSave
    
    # Customize Packet
    # packet[Ether].src = src_mac  # Disrupts
    # packet[Ether].dst = dst_mac  # Disrupts

    # packet[IP].ihl = 5  # Good if equal to 5 (5 * 4 = 20 bytes)
    # packet[IP].len = 67 # Good with or without
    # packet[IP].id = 61351
    # packet[IP].flags = 'DF'
    # packet[IP].chksum = 0xf0bd
    # packet[IP].src = src_IP  # Source IP address
    # packet[IP].dst = dst_IP  # Destination IP address

    # packet[TCP].sport = DNP3_PORT_NUMBER  # Source port
    # packet[TCP].dport = 48726  # Destination port]
    # packet[TCP].seq = 4046735747
    # packet[TCP].ack = 3782547931
    # packet[TCP].dataofs = 8
    # packet[TCP].reserved = 0
    # packet[TCP].flags = 'PA'
    # packet[TCP].window = 8192
    # packet[TCP].chksum = 0x2db1
    # packet[TCP].urgptr = 0
    # packet[TCP].options = [('NOP', None), ('NOP', None), ('Timestamp', (351399, 246451345))]


    # packet[DNP3].length = 10
    # packet[DNP3].destination = 4
    # packet[DNP3].source = 2
    # tempControl = DataLinkLayerControl()
    # tempControl.DIR = 0
    # packet[DNP3].control = tempControl
    # packet[DNP3].crc = 0xfa4a
    # packet[TransportControl].final = 'set'
    # packet[TransportControl].first = 'set'
    # packet[TransportControl].sequence = 20
    # tempAppControl = ApplicationControl()
    # tempAppControl.confirm = 0
    # tempAppControl.unsolicited = 0
    # tempAppControl.sequence = 11
    # packet[ApplicationLayer].Application_Control = tempAppControl
    # packet[ApplicationLayer].Function_Code = 129
    # XShortField("crc", None),
    packet.show()

    return packet


src_mac = '00:20:75:20:d2:fa'
dst_mac = '00:90:4f:e5:38:a1'

pcapList = []
pcapList.append(create_DNP3_packet(src_mac, dst_mac,"172.28.2.10", "172.28.2.20", 0x01, 0x01))
wrpcap("scada_traffic.pcap", pcapList)
