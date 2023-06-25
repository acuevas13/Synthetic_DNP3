from dnp3_dissector import *
from scapy.all import *
from cycleDetect import *

DNP3_PORT_NUMBER = 20000  # Set the DNP3 port number used in your packets

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
    packet = getPacket(pcapFile, 8)
    
    # Fill in Packet
    tempControl = DataLinkLayerControl()
    tempControl.DIR = 1
    tempControl.PRM = 1
    tempControl.FCB = 0
    tempControl.FCV = 0
    tempControl.funcation_code_primary = 4
    
    packet[DNP3] = DNP3(length=17, control=tempControl,
                        destination=1, source=1, crc=60008)
    # packet[DNP3].length = 17
    # packet[DNP3].control = tempControl
    # packet[DNP3].destination = 1
    # packet[DNP3].source = 1
    # packet[DNP3].crc = 60008

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
dst_mac = '00:27:90:d4:eb:21'

pcapList = []
pcapList.append(create_DNP3_packet(src_mac, dst_mac,"172.28.2.10", "172.28.0.11", 0x01, 0x01))
wrpcap("scada_traffic.pcap", pcapList)
