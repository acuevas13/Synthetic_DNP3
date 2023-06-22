from dnp3_dissector import *
from scapy.all import *
from cycleDetect import *


# pcapFile = "../B/siabmgrB2-1300-filtered.pcap"
# pcapFile = "../B/siabmgrA5-20191030-174849.pcap"

# tokenized = multiTokenizer(pcapFile)


# for i in range(10):
#     packet = Ether()/IP()/TCP()/DNP3()
#     # Customize fields
#     wrpcap(f"synthetic_traffic_{i}.pcap", packet)


# def create_modbus_packet(transaction_id, unit_id, function_code, starting_address, quantity):
#     # Create the Modbus TCP packet
#     packet = Ether() / IP(dst="RTU_IP_ADDRESS") / TCP(dport=502)

#     # Modbus TCP header
#     packet[TCP].sport = RandNum(1024, 65535)  # Randomize source port
#     packet[TCP].flags = "PA"  # Push and Acknowledge flags
#     packet[TCP].seq = RandNum(1, 4294967295)  # Randomize sequence number
#     packet[TCP].ack = 0

DNP3_PORT_NUMBER = 20000  # Set the DNP3 port number used in your packets


def calculate_checksum(data):
    # Custom logic to calculate the checksum
    checksum = 0
    for byte in data:
        checksum += byte
    return checksum & 0xFFFF

def create_DNP3_packet(src_mac, dst_mac, src_IP, dst_IP, function_code, relay_status):
    # Construct the packet with necessary layers
    pcapFile = "../B/siabmgrB2-1300-filtered.pcap"
    # packet = Ether()/IP()/TCP()/DNP3()/TransportControl()/ApplicationLayer()
    
    packet = None
    for p in PcapReader(pcapFile):
        if ApplicationLayer in p:
            packet = p
            p.show()
            # return p
            break
    
    # Customize packet fields
    # packet[Ether].src = src_mac  # Disrupts
    print(packet[Ether].dst)
    print(len(packet[Ether].dst))
    print(len(packet))
    packet[Ether].dst = dst_mac  # Disrupts
    print(packet[Ether].dst)
    print(len(packet[Ether].dst))
    print(len(packet.wirelen))
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
    # # packet[TCP].urgptr = 0
    # packet[TCP].options = [('NOP', None), ('NOP', None), ('Timestamp', (351399, 246451345))]

    # Calculate the checksum and insert after every 16 bytes of data
    # dnp3_with_checksum = b''
    # for i in range(0, len(packet), 16):
    #     chunk = packet[i:i+16]
    #     checksum = calculate_checksum(chunk)
    #     dnp3_with_checksum += chunk + struct.pack('!H', checksum)

    # Update the DNP3 layer with the data including checksum
    # packet[DNP3].data = dnp3_with_checksum

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
    # packet.show()

    return packet



# try:
#     # Register the DNP3 dissector with the DNP3 port number
#     # Bind UDP packets on DNP3 port
#     bind_layers(UDP, DNP3, dport=DNP3_PORT_NUMBER)
#     bind_layers(UDP, DNP3, sport=DNP3_PORT_NUMBER)

#     # Bind TCP packets on DNP3 port
#     bind_layers(TCP, DNP3, dport=DNP3_PORT_NUMBER)
#     bind_layers(TCP, DNP3, sport=DNP3_PORT_NUMBER)

    
# except ImportError:
#     print("DNP3 dissector not available in Scapy.")

src_mac = '00:20:75:20:d2:fa'
dst_mac = '00:27:90:d4:eb:21'

pcapList = []
# Create a packet for a SCADA message to open Relay 1
# pcapList.append(create_DNP3_packet(src_mac, dst_mac,"172.28.2.10", "172.28.0.11", 0x01, 0x01))

# # Create a packet for a SCADA message to close Relay 2
# pcapList.append(create_DNP3_packet(src_mac, dst_mac, "192.168.0.1", "192.168.0.2", 0x02, 0x00))

# # Create a packet for a SCADA message to toggle Relay 3
# pcapList.append((create_DNP3_packet(src_mac, dst_mac, "192.168.0.1", "192.168.0.2", 0x03, 0x02)))

# Save packets to a pcap file
# wrpcap("scada_traffic.pcap", pcapList)
pcapFile = "../B/siabmgrB2-1300-filtered.pcap"
wrpcap('scada_traffic.pcap', rdpcap(pcapFile))
