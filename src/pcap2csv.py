from dnp3_dissector import *
from scapy.all import *
import sys
import time
import csv

# Global Variables
conf.layers.filter([Ether, IP, TCP, UDP, DNP3]) # Check for speed
maxSigned16bitNumber = (2**15)-1
signedCorrectionOffset = (2**16)
maxNumberOfPoints = 200

lastRow = {}
binaryObj_Static_RespToPoll = 1
binaryObj_Changed_RespToPoll = 2 # Contains no pointNumber, obtain value from quality
analogObjs_StaticAndChanged_RespToPoll = [30, 32]

objVarsWithOnlyQualityFlag = [(2,1), (2,2), (1,2)]
allObjsToRecord = [1, 2, 30, 32]
objsWithIndex = [(32,2), (32,4), (2,2), (2,1)]

ackNum = -1
seqNum = -1
absTime = 0
currTime = 0
pktNumber = 0

# Determine ABB vs SEL point map 
SEL_OUI = "00:30:a7"
ABB_OUI = "00:90:4f"
OUI = "" # Organizationally Unique Identifier

# CSV Definition
SEL_mapPcapToCSV = {'PKT' : None,
                    'TIME': None,
                    'RELAY': None,
                    'OPEN': 'BI:23',
                    'VA': 'AI:9',
                    'VB': 'AI:10',
                    'VC': 'AI:11',
                    'IA': 'AI:1',
                    'IB': 'AI:2',
                    'IC': 'AI:3',
                    'IN': 'AI:5',
                    'PI' : 'AI:13',
                    'PV' : 'AI:16',
                    'PZV': 'AI:19',
                    'FREQ': 'AI:0',
                    }

ABB_mapPcapToCSV = {'PKT' : None,
                    'TIME': None,
                    'RELAY': None,
                    'OPEN': 'BI:13',
                    'VA': 'AI:9',
                    'VB': 'AI:10',
                    'VC': 'AI:11',
                    'IA': 'AI:1',
                    'IB': 'AI:2',
                    'IC': 'AI:3',
                    'IN': 'AI:5',
                    'FREQ': 'AI:0',
                    }

binaryIndexesDict = {}
analogIndexesDict = {}
header = []

f = open('output.csv', 'w')
writer = csv.writer(f)

# --------------- ABB - B2 ---------------
# RTU_IPAddress = '172.28.2.10'
# pcapFile = "/data/netgen/B/testB2-1300-filtered.pcap"
# pcapFile = "/data/netgen/B/siabmgrB2-1800-filtered.pcap"
# pcapFile = "/data/netgen/B/siabmgrB2-1900-filtered.pcap"
# pcapFile = "/data/netgen/B/siabmgrB2-1300-filtered.pcap"
# pcapFile = "/data/netgen/B/siabmgrB2-1700-filtered.pcap"
# pcapFile = "/data/netgen/B/siabmgrB2-1600-filtered.pcap"
# pcapFile = "/data/netgen/B/siabmgrB2-1500-filtered.pcap"
# pcapFile = "/data/netgen/B/siabmgrB2-1400-filtered.pcap"

# --------------- SEL - A4 ---------------
# RTU_IPAddress = '172.27.4.11'
# pcapFile = "/data/netgen/siabmgrA4/siabmgrA4-20191028-161710.pcap"
# pcapFile = "/data/netgen/siabmgrA4/siabmgrA4-20191029-160751.pcap"

# --------------- SEL - A5 ---------------
# RTU_IPAddress = "172.27.5.11"
# pcapFile = "/data/netgen/siabmgrA5/siabmgrA5-20191030-174849.pcap"
# pcapFile = "/data/netgen/siabmgrA5/siabmgrA5-20191101-131433.pcap"

# --------------- SEL - From Lab ---------------
RTU_IPAddress = "172.20.2.10"
pcapFile = "/data/netgen/A_selPCAPFromlab/breaker-ops-on-c2-c1-feed.pcap"

def initPointMaps(mapPcapToCSV):
    global header, binaryIndexesDict, analogIndexesDict
    header = list(mapPcapToCSV.keys())
    writer.writerow(header)
    
    for i in range(len(header)):
        colName = header[i]
        currColVal = mapPcapToCSV[colName]
        if currColVal == None:
            continue
        
        dataType, pointNumber = currColVal.split(":")
        if dataType == 'BI':
            binaryIndexesDict[pointNumber]  = colName
        if dataType == 'AI':
            analogIndexesDict[str(pointNumber)]  = colName
        
startTime = time.time()
for p in PcapReader(pcapFile):
    pktNumber += 1
    # Only scan responses to master, ignore master to slave
    if IP in p and p[IP].dst != RTU_IPAddress:
        continue 

    # Ignore TCP Retransmisions
    if TCP in p and p[TCP].seq == seqNum and p[TCP].ack == ackNum:
        continue
    
    if ApplicationResponse in p:
        if OUI == "":
            macAddress = p[Ether].src
            OUI = macAddress[0:8]
            if OUI == ABB_OUI:
                initPointMaps(ABB_mapPcapToCSV)
            elif OUI == SEL_OUI:
                initPointMaps(SEL_mapPcapToCSV)
            else:
                continue

        seqNum = p[TCP].seq
        ackNum = p[TCP].ack
        
        if absTime == 0:
            absTime = p.time
        currTime = p.time - absTime
        print(f"pktNumber: {pktNumber}, time: {currTime}")
        
        currRelay = str(p[IP].src)
        if currRelay not in lastRow:
            lastRow[currRelay] = ["Na"] * len(header)
        lastRow[currRelay][header.index('PKT')] = pktNumber
        lastRow[currRelay][header.index('TIME')] = currTime
        lastRow[currRelay][header.index('RELAY')] = currRelay

        obj, var = 0, 0
        currAppRespLayer = p[ApplicationResponse]
        while currAppRespLayer.payload:
            obj = currAppRespLayer.Object
            var = currAppRespLayer.Var
            dataClass = currAppRespLayer.payload
            
            if obj not in allObjsToRecord:
                currAppRespLayer = currAppRespLayer.payload.payload
                continue
            
            for j in range(maxNumberOfPoints):
                pointNumber = str(j)
                # Fix indices
                if (obj, var) in objsWithIndex:
                    prefixCode = dataClass.QualiferField.PrefixCode
                    indexName = ""
                    if prefixCode == 1:
                        indexName = 'Index_8bit_'
                    if prefixCode == 2:
                        indexName = 'Index_16bit_'
                    if prefixCode == 3:
                        indexName = 'Index_32bit_'
                    indexValue = dataClass.getfieldval(indexName + str(j))
                    if indexValue == None:
                        break
                    pointNumber = str(indexValue)
                    
                if (obj,var) in objVarsWithOnlyQualityFlag:
                    if pointNumber in binaryIndexesDict:
                        colName = binaryIndexesDict[pointNumber]
                        colIndex = header.index(colName)
                        quality = dataClass.getfieldval("Quality_BinaryInput" + str(j))
                        lastRow[currRelay][colIndex] = quality.Point_Value
                    continue
                    
                pointValue = dataClass.getfieldval('PointNumber' + str(j))
                if pointValue == None:
                    break
                
                if pointValue > maxSigned16bitNumber:
                    pointValue -= signedCorrectionOffset
                    
                if obj == binaryObj_Static_RespToPoll and pointNumber in binaryIndexesDict:
                    colName = binaryIndexesDict[pointNumber]
                    colIndex = header.index(colName)
                    lastRow[currRelay][colIndex] = pointValue
                    
                if obj in analogObjs_StaticAndChanged_RespToPoll and pointNumber in analogIndexesDict:
                    colName = analogIndexesDict[pointNumber]
                    colIndex = header.index(colName)
                    lastRow[currRelay][colIndex] = pointValue
            currAppRespLayer = currAppRespLayer.payload.payload
        writer.writerow(lastRow[currRelay])
        
print(f"Time: {time.time() - startTime}, Packets: {pktNumber}")
f.close()