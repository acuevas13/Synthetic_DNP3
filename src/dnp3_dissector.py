from scapy.all import *
import crcmod.predefined

DNP3_PORT_NUMBER = 20000
DNP3_START_BYTES = 0x0564
MASTER = 1
OUTSTATION = 0
SET = 1
UNSET = 0
maxNumberOfPoints = 200

binaryGroup = [(1,1)]
pointGroup = [(30,2), (30,4), (32,2), (32,4), (10,2), (2,2), (2,1), (1,2)]
selectGroup = [(12,1)]

objVarsWithIndex = [(32,2), (32,4), (2,2), (2,1), (12,1)]
objVarsWithPointNumber = [(1,1), (30,4), (30,2), (32,2), (32,4)]
ObjVarsWithTimeStamp = [(2,2), (32,4)]

objVarsWithBinaryInputQuality = [(1,2), (2,1), (2,2)]
objVarsWithBinaryOutputQuality = [(10, 2), (12, 1)]
objVarsWithAnalogInputQuality = [(30, 2), (32,2), (32,4)]
# objVarsWithAnalogOutputQuality = [40, 41]

primaryFunctCodes = {
    0: "reset_link_states",
    2: "test_link_states",
    3: "confirmed_user_data",
    4: "unconfirmed_user_data",
    9: "request_link_status",
}

secondaryFunctCodes = {
    0: "ACK",
    1: "NACK",
    11: "link_status",
    15: "not_supported",
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

qualiferRangeCodes = {
    0: "8-bit_start_stop_indices",
    1: "16-bit_start_stop_indices",
    2: "32-bit_start_stop_indices",
    3: "8-bit_absoulte_addresses",
    4: "16-bit_absoulte_addresses",
    5: "32-bit_absoulte_addresses",
    6: "length_of_range_is_zero",
    7: "8-bit_single_field_quantity",
    8: "16-bit_single_field_quantity",
    9: "32-bit_single_field_quantity",
    10: "reserved",
    11: "free-format_qualifier",
    12: "reserved",
    13: "reserved",
    14: "reserved",
    15: "reserved",
}

qualiferPrefixCodes = {
    0: "no_index",
    1: "1-octet_index",
    2: "2-octet_index",
    3: "4-octet_index",
    4: "1-octet_object_size",
    5: "2-octet_object_size",
    6: "4-octet_object_size"
}    
    
tripControlCodes = {
    0: "null",
    1: "close",
    2: "trip",
    3: "reserved"
}

queueClearFieldCodes = {
    0: "not_set",
    1: "queue",
    2: "clear",
    3: "queue_and_clear"
}

operationTypeCodes = {
    0: "null_operation",
    1: "pulse_on",
    2: "pulse_off",
    3: "latch_on",
    4: "latch_off"
}

controlStatusCodes = {
    0: "req_accepted/init/queued",
    1: "req_not_accepted;arm_timer_expired",
    2: "req_not_accepted;no_SELECT_received",
    3: "req_not_accepted;format_error_in_ctl_req",
    4: "ctl_oper_not_supported_for_this_point",
    5: "req_not_accepted;ctrl_queue_full/point_active",
    6: "req_not_accepted;ctrl_hardware_problems",
    7: "req_not_accepted;local/remote_switch_in_local",
    8: "req_not_accepted;too_many_operations",
    9: "req_not_accepted;insufficient_authorization",
    10: "req_not_accepted;local_automation_proc_active",
    11: "req_not_accepted;processing_limited",
    12: "req_not_accepted;out_of_range_value",
    126: "req_not_accepted;non_participating_(NOP_req)",
    127: "req_not_accepted;undefined_error",
}

deviceTypeEnum = {
    0: "outstation",
    1: "master"
}

bitEnum = {
    0: "unset",
    1: "set"
}


def crc16DNP(data):
    crc16_fn = crcmod.predefined.mkPredefinedCrcFun('crc-16-dnp')
    crcINT = crc16_fn(data)
    print(f"crcINT: {crcINT}")
    crcSTR = str(crc16_fn(data))
    print(f"crcSTR!!!: {crcSTR}")

    crcBytes = crcINT.to_bytes((crcINT.bit_length() + 7) // 8, "big")
    print(f"crcBytes: {crcBytes}")
    return crcBytes


class ApplicationSelectControlCode(Packet):
    name = "Application Control Code"
    fields_desc = [
        BitEnumField("Trip_Control_Code", 1, 2, tripControlCodes),
        BitEnumField("Queue_Clear_Field", 1, 2, queueClearFieldCodes),
        BitEnumField("Operation_Type", 1, 4, operationTypeCodes),
    ]

    def extract_padding(self, p):
        return "", p
    
class ApplicationSelectControlStatus(Packet):
    name = "Application Control Status"
    fields_desc = [
        BitEnumField("reserved", 0, 1, bitEnum),
        BitEnumField("Control_Status", 0, 7, controlStatusCodes),
    ]

    def extract_padding(self, p):
        return "", p
    
class ApplicationControl(Packet):
    name = "Application Control"
    fields_desc = [
        BitEnumField("first", 1, 1, bitEnum),
        BitEnumField("final", 1, 1, bitEnum),
        BitEnumField("confirm", 1, 1, bitEnum),
        BitEnumField("unsolicited", 1, 1, bitEnum),
        BitField("sequence", 1, 4),
    ]

    def extract_padding(self, p):
        return "", p

class ApplicationInternalIndications(Packet):
    name = "Internal Indications"
    fields_desc = [
        BitEnumField("device_restart", UNSET, 1, bitEnum),
        BitEnumField("device_trouble", UNSET, 1, bitEnum),
        BitEnumField("digital_outputs_in_local", UNSET, 1, bitEnum),
        BitEnumField("time_sync_required", UNSET, 1, bitEnum),
        BitEnumField("class_3_data_available", UNSET, 1, bitEnum),
        BitEnumField("class_2_data_available", UNSET, 1, bitEnum),
        BitEnumField("class_1_data_available", UNSET, 1, bitEnum),
        BitEnumField("broadcast_msg_rx", UNSET, 1, bitEnum),
        BitEnumField("reserved_1", UNSET, 1, bitEnum),
        BitEnumField("reserved_2", UNSET, 1, bitEnum),
        BitEnumField("configuration_corrupt", UNSET, 1, bitEnum),
        BitEnumField("operation_already_executing", UNSET, 1, bitEnum),
        BitEnumField("event_buffer_overflow", UNSET, 1, bitEnum),
        BitEnumField("paramter_invalid_outOfRange", UNSET, 1, bitEnum),
        BitEnumField("requested_objects_unknown", UNSET, 1, bitEnum),
        BitEnumField("funcation_code_not_implemented", UNSET, 1, bitEnum),
    ]

    def extract_padding(self, p):
        return "", p

class DataObjectQualifer(Packet):
    name = "Data_Object_Qualifer"
    fields_desc = [
        BitEnumField("reserved", 0, 1, bitEnum),
        BitEnumField("PrefixCode", 0, 3, qualiferPrefixCodes),
        BitEnumField("RangeCode", 0, 4, qualiferRangeCodes),
    ]
    def extract_padding(self, p):
        return "", p

class BinaryInputQualityFlags(Packet):
    name = "Quality"
    fields_desc = [
        BitField("Point_Value", None, 1),
        BitEnumField("reserved", UNSET, 1, bitEnum),
        BitEnumField("Chatter_Filter", UNSET, 1, bitEnum),
        BitEnumField("Local_Force", UNSET, 1, bitEnum),
        BitEnumField("Remote_Force", UNSET, 1, bitEnum),
        BitEnumField("Comm_Fail", UNSET, 1, bitEnum),
        BitEnumField("Restart", UNSET, 1, bitEnum),
        BitEnumField("Online", UNSET, 1, bitEnum),
    ]

    def extract_padding(self, p):
        return "", p
    
class BinaryOutputQualityFlags(Packet):
    name = "Quality"
    fields_desc = [
        BitField("Point_Value", None, 1),
        BitEnumField("reserved1", UNSET, 1, bitEnum),
        BitEnumField("reserved2", UNSET, 1, bitEnum),
        BitEnumField("Local_Force", UNSET, 1, bitEnum),
        BitEnumField("Remote_Force", UNSET, 1, bitEnum),
        BitEnumField("Comm_Fail", UNSET, 1, bitEnum),
        BitEnumField("Restart", UNSET, 1, bitEnum),
        BitEnumField("Online", UNSET, 1, bitEnum),
    ]

    def extract_padding(self, p):
        return "", p

class AnalogInputQualityFlags(Packet):
    name = "Quality"
    fields_desc = [
        BitEnumField("reserved", UNSET, 1, bitEnum),
        BitEnumField("Reference_Check", UNSET, 1, bitEnum),
        BitEnumField("Over_Range", UNSET, 1, bitEnum),
        BitEnumField("Local_Force", UNSET, 1, bitEnum),
        BitEnumField("Remote_Force", UNSET, 1, bitEnum),
        BitEnumField("Comm_Fail", UNSET, 1, bitEnum),
        BitEnumField("Restart", UNSET, 1, bitEnum),
        BitEnumField("Online", UNSET, 1, bitEnum),
    ]

    def extract_padding(self, p):
        return "", p
    
class AnalogOutputQualityFlags(Packet):
    name = "Quality"
    fields_desc = [
        BitEnumField("reserved1", UNSET, 1, bitEnum),
        BitEnumField("reserved2", UNSET, 1, bitEnum),
        BitEnumField("reserved3", UNSET, 1, bitEnum),
        BitEnumField("Local_Force", UNSET, 1, bitEnum),
        BitEnumField("Remote_Force", UNSET, 1, bitEnum),
        BitEnumField("Comm_Fail", UNSET, 1, bitEnum),
        BitEnumField("Restart", UNSET, 1, bitEnum),
        BitEnumField("Online", UNSET, 1, bitEnum),
    ]

    def extract_padding(self, p):
        return "", p
     
class BinaryInputDataClass_SS8(Packet):
    name = "Single 8-bit Binary Input"
    fields_desc = [
        PacketField("QualiferField", DataObjectQualifer(), DataObjectQualifer),
        BitField("Start", None, -8),
        BitField("Stop", None, -8)
    ]
    
    byte_num = 8
    for otc in range(32):
        for i in range(byte_num-1, byte_num-9, -1):
            bi = ConditionalField(BitField("PointNumber" + str(i), 0, 1), \
                lambda pkt, pList=objVarsWithPointNumber, b=byte_num: math.ceil(pkt.Stop/8)*8 >= b and \
                    (pkt.underlayer.Object, pkt.underlayer.Var) in pList)
            fields_desc.append(bi)
            
        byte_num +=8
        
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return ApplicationResponse
        return Packet.guess_payload_class(self, payload)


class PointDataClass_SS8(Packet):
    name = "PointDataClass_SS8"
    
    fields_desc = [
        PacketField("QualiferField", DataObjectQualifer(), DataObjectQualifer),
        BitField("Start", None, -8),
        BitField("Stop", None, -8),
    ]
    
    for i in range(maxNumberOfPoints):
        fields_desc.append( ConditionalField(BitField("Index_8bit_" + str(i), None, -8), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 1 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum <= pkt.Stop)),
        
        fields_desc.append( ConditionalField(BitField("Index_16bit_" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 2 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum <= pkt.Stop)),
        
        fields_desc.append( ConditionalField(BitField("Index_32bit_" + str(i), None, -32), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 3 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum <= pkt.Stop)),
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryInput" + str(i), BinaryInputQualityFlags(), BinaryInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryOutput" + str(i), BinaryOutputQualityFlags(), BinaryOutputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryOutputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(PacketField("Quality_AnalogInput" + str(i), AnalogInputQualityFlags(), AnalogInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithAnalogInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
                         
        fields_desc.append( ConditionalField(BitField("PointNumber" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithPointNumber: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
                    
        fields_desc.append( ConditionalField(BitField("TimeStamp" + str(i), None, -48), \
            lambda pkt, pNum=i, pList=ObjVarsWithTimeStamp: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
                 
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return ApplicationResponse
        return Packet.guess_payload_class(self, payload)

class PointDataClass_SS16(Packet):
    name = "PointDataClass_SS16"
    
    fields_desc = [
        PacketField("QualiferField", DataObjectQualifer(), DataObjectQualifer),
        BitField("Start", None, -16),
        BitField("Stop", None, -16),
    ]
        
    for i in range(maxNumberOfPoints):
        fields_desc.append( ConditionalField(BitField("Index_8bit_" + str(i), None, -8), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 1 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum <= pkt.Stop)),
        
        fields_desc.append( ConditionalField(BitField("Index_16bit_" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 2 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum <= pkt.Stop)),
        
        fields_desc.append( ConditionalField(BitField("Index_32bit_" + str(i), None, -32), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 3 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum <= pkt.Stop)),
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryInput" + str(i), BinaryInputQualityFlags(), BinaryInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryOutput" + str(i), BinaryOutputQualityFlags(), BinaryOutputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryOutputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(PacketField("Quality_AnalogInput" + str(i), AnalogInputQualityFlags(), AnalogInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithAnalogInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(BitField("PointNumber" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithPointNumber: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(BitField("TimeStamp" + str(i), None, -48), \
            lambda pkt, pNum=i, pList=ObjVarsWithTimeStamp: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return ApplicationResponse
        return Packet.guess_payload_class(self, payload)

class PointDataClass_SS32(Packet):
    name = "PointDataClass_SS32"
    
    fields_desc = [
        PacketField("QualiferField", DataObjectQualifer(), DataObjectQualifer),
        BitField("Start", None, -32),
        BitField("Stop", None, -32),
    ]
        
    for i in range(maxNumberOfPoints):
        fields_desc.append( ConditionalField(BitField("Index_8bit_" + str(i), None, -8), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 1 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum <= pkt.Stop)),
        
        fields_desc.append( ConditionalField(BitField("Index_16bit_" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 2 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum <= pkt.Stop)),
        
        fields_desc.append( ConditionalField(BitField("Index_32bit_" + str(i), None, -32), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 3 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum <= pkt.Stop)),
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryInput" + str(i), BinaryInputQualityFlags(), BinaryInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryOutput" + str(i), BinaryOutputQualityFlags(), BinaryOutputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryOutputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(PacketField("Quality_AnalogInput" + str(i), AnalogInputQualityFlags(), AnalogInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithAnalogInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(BitField("PointNumber" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithPointNumber: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
        fields_desc.append( ConditionalField(BitField("TimeStamp" + str(i), None, -48), \
            lambda pkt, pNum=i, pList=ObjVarsWithTimeStamp: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum <= pkt.Stop))
        
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return ApplicationResponse
        return Packet.guess_payload_class(self, payload)

class PointDataClass_SF8(Packet):
    name = "PointDataClass_SF8"
    
    fields_desc = [
        PacketField("QualiferField", DataObjectQualifer(), DataObjectQualifer),
        BitField("Number_Of_Items", None, -8)
    ]
        
    for i in range(maxNumberOfPoints):
        fields_desc.append( ConditionalField(BitField("Index_8bit_" + str(i), None, -8), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 1 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(BitField("Index_16bit_" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 2 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(BitField("Index_32bit_" + str(i), None, -32), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 3 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryInput" + str(i), BinaryInputQualityFlags(), BinaryInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryOutput" + str(i), BinaryOutputQualityFlags(), BinaryOutputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryOutputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(PacketField("Quality_AnalogInput" + str(i), AnalogInputQualityFlags(), AnalogInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithAnalogInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(BitField("PointNumber" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithPointNumber: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(BitField("TimeStamp" + str(i), None, -48), \
            lambda pkt, pNum=i, pList=ObjVarsWithTimeStamp: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return ApplicationResponse
        return Packet.guess_payload_class(self, payload)

class PointDataClass_SF16(Packet):
    name = "PointDataClass_SF16"
    
    fields_desc = [
        PacketField("QualiferField", DataObjectQualifer(), DataObjectQualifer),
        BitField("Number_Of_Items", None, -16)
    ]
        
    for i in range(maxNumberOfPoints):
        fields_desc.append( ConditionalField(BitField("Index_8bit_" + str(i), None, -8), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 1 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(BitField("Index_16bit_" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 2 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(BitField("Index_32bit_" + str(i), None, -32), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 3 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryInput" + str(i), BinaryInputQualityFlags(), BinaryInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryOutput" + str(i), BinaryOutputQualityFlags(), BinaryOutputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryOutputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(PacketField("Quality_AnalogInput" + str(i), AnalogInputQualityFlags(), AnalogInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithAnalogInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(BitField("PointNumber" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithPointNumber: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(BitField("TimeStamp" + str(i), None, -48), \
            lambda pkt, pNum=i, pList=ObjVarsWithTimeStamp: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return ApplicationResponse
        return Packet.guess_payload_class(self, payload)

class PointDataClass_SF32(Packet):
    name = "PointDataClass_SF32"
    
    fields_desc = [
        PacketField("QualiferField", DataObjectQualifer(), DataObjectQualifer),
        BitField("Number_Of_Items", None, -32)
    ]
        
    for i in range(maxNumberOfPoints):
        fields_desc.append( ConditionalField(BitField("Index_8bit_" + str(i), None, -8), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 1 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(BitField("Index_16bit_" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 2 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(BitField("Index_32bit_" + str(i), None, -32), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 3 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryInput" + str(i), BinaryInputQualityFlags(), BinaryInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(PacketField("Quality_BinaryOutput" + str(i), BinaryOutputQualityFlags(), BinaryOutputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithBinaryOutputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(PacketField("Quality_AnalogInput" + str(i), AnalogInputQualityFlags(), AnalogInputQualityFlags), \
            lambda pkt, pNum=i, pList=objVarsWithAnalogInputQuality: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(BitField("PointNumber" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithPointNumber: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
        fields_desc.append( ConditionalField(BitField("TimeStamp" + str(i), None, -48), \
            lambda pkt, pNum=i, pList=ObjVarsWithTimeStamp: (pkt.underlayer.Object, pkt.underlayer.Var) in pList and \
                pNum < pkt.Number_Of_Items))
        
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return ApplicationResponse
        return Packet.guess_payload_class(self, payload)
    
class SelectDataClass(Packet):
    name = "Control Relay Output Block"
    
    fields_desc = [
        PacketField("QualiferField", DataObjectQualifer(), DataObjectQualifer),
        BitField("Number_Of_Items", None, -16),
    ]

    for i in range(maxNumberOfPoints):
        fields_desc.append( ConditionalField(BitField("Index_8bit_" + str(i), None, -8), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 1 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(BitField("Index_16bit_" + str(i), None, -16), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 2 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(BitField("Index_32bit_" + str(i), None, -32), \
            lambda pkt, pNum=i, pList=objVarsWithIndex: pkt.QualiferField.PrefixCode == 3 and \
                (pkt.underlayer.Object, pkt.underlayer.Var) in pList and pNum < pkt.Number_Of_Items)),
        
        fields_desc.append( ConditionalField(PacketField("ControlCode" + str(i), ApplicationSelectControlCode(), ApplicationSelectControlCode), \
            lambda pkt, pNum=i: (pNum < pkt.Number_Of_Items)))
        
        fields_desc.append( ConditionalField(BitField("Count" + str(i), None, -8), \
            lambda pkt, pNum=i: (pNum < pkt.Number_Of_Items)))
        
        fields_desc.append( ConditionalField(BitField("On_Time" + str(i), None, -32), \
            lambda pkt, pNum=i: (pNum < pkt.Number_Of_Items)))
        
        fields_desc.append( ConditionalField(BitField("Off_Time" + str(i), None, -32), \
            lambda pkt, pNum=i: (pNum < pkt.Number_Of_Items)))
        
        fields_desc.append( ConditionalField(PacketField("ControlStatus" + str(i), ApplicationSelectControlStatus(), ApplicationSelectControlStatus), \
            lambda pkt, pNum=i: (pNum < pkt.Number_Of_Items)))
        
    def guess_payload_class(self, payload):
        if len(payload) > 0:
            return ApplicationResponse
        return Packet.guess_payload_class(self, payload)

class ApplicationResponse(Packet):
    name = "Application Response"
    fields_desc = [
        ByteField("Object", None),
        ByteField("Var", None),
    ]
    
    def guess_payload_class(self, payload):
        if len(payload) == 0:
            return Packet.guess_payload_class(self, payload)

        if (self.Object, self.Var) in binaryGroup:
            return  BinaryInputDataClass_SS8
        if (self.Object, self.Var) in pointGroup:
            qualiferCode = f'{payload[0]:08b}'
            # prefixCode = int(qualiferCode[1:4], 2)
            rangeCode = int(qualiferCode[4:8], 2)
            if rangeCode == 0:
                return  PointDataClass_SS8
            if rangeCode == 1:
                return  PointDataClass_SS16
            if rangeCode == 2:
                return  PointDataClass_SS32
            if rangeCode == 7:
                return  PointDataClass_SF8
            if rangeCode == 8:
                return  PointDataClass_SF16
            if rangeCode == 9:
                return  PointDataClass_SF32
        if (self.Object, self.Var) in selectGroup:
            return  SelectDataClass
        return Packet.guess_payload_class(self, payload)

class ApplicationRequest(Packet):
    name = "Application Request"
    fields_desc = [
        ByteField("Object0", None),
        ByteField("Var0", None),
        PacketField("QualiferField0", DataObjectQualifer(),
                    DataObjectQualifer),
        ByteField("Object1", None),
        ByteField("Var1", None),
        PacketField("QualiferField1", DataObjectQualifer(),
                    DataObjectQualifer),
        ByteField("Object2", None),
        ByteField("Var2", None),
        PacketField("QualiferField2", DataObjectQualifer(),
                    DataObjectQualifer),
        ByteField("Object3", None),
        ByteField("Var3", None),
        PacketField("QualiferField3", DataObjectQualifer(), DataObjectQualifer),
    ]
    
    def guess_payload_class(self, payload):
        return Packet.guess_payload_class(self, payload)

class ApplicationLayer(Packet):
    name = "Application Layer"
    fields_desc = [
        PacketField("Application_Control", ApplicationControl(), ApplicationControl),
        BitEnumField("Function_Code", 1, 8, applicationFunctCodes),
        ConditionalField(PacketField("Internal_Indications", ApplicationInternalIndications(), ApplicationInternalIndications), \
            lambda pkt: (pkt.Function_Code == 129)),
    ]
    
    def pre_dissect(self, s: bytes):
        numDataChunks = (len(s) + 1) // 18
        remainderData = (len(s) + 1) % 18
        startCRCIndex = 15
        replCRCIndexList = []
        while numDataChunks > 0:
            replCRCIndexList.append(startCRCIndex)
            replCRCIndexList.append(startCRCIndex+1)
            
            startCRCIndex += 18
            numDataChunks -= 1
            
        s = [i for j, i in enumerate(s) if j not in replCRCIndexList]
        s = bytes(s)
        
        if remainderData != 0:
            s = s[:-2]

        return s
    
    def guess_payload_class(self, payload):
        if self.Function_Code == 129:
            return ApplicationResponse
        elif self.Function_Code == 1:
            return ApplicationRequest
        return Packet.guess_payload_class(self, payload)


class TransportControl(Packet):
    name = "Transport Control"
    fields_desc = [
        BitEnumField("final", None, 1, bitEnum),
        BitEnumField("first", None, 1, bitEnum),
        BitField("sequence", None, 6),
    ]

    def guess_payload_class(self, payload):
        return ApplicationLayer

class DataLinkLayerControl(Packet):
    name = "Control"

    fields_desc = [
        BitEnumField("DIR", MASTER, 1, deviceTypeEnum),
        BitEnumField("PRM", MASTER, 1, deviceTypeEnum),
        ConditionalField(BitEnumField("FCB", 0, 1, bitEnum), lambda x:x.PRM == MASTER),
        ConditionalField(BitEnumField("FCV", 0, 1, bitEnum), lambda x:x.PRM == MASTER),
        ConditionalField(BitEnumField("funcation_code_primary", 4, 4, primaryFunctCodes), lambda x:x.PRM == MASTER),
        ConditionalField(BitEnumField("reserved", 0, 1, bitEnum), lambda x:x.PRM == OUTSTATION),
        ConditionalField(BitEnumField("DFC", 0, 1, bitEnum), lambda x:x.PRM == OUTSTATION),
        ConditionalField(BitEnumField("funcation_code_secondary", 4, 4, secondaryFunctCodes), lambda x:x.PRM == OUTSTATION),
    ]

    def extract_padding(self, p):
        return "", p

class DNP3(Packet):
    name = "DNP3"
    fields_desc = [
        XShortField("start", DNP3_START_BYTES),
        ByteField("length", None),
        PacketField("control", None, DataLinkLayerControl),
        LEShortField("destination", None),
        LEShortField("source", None),
        XShortField("crc", None),
    ]
    
    data_chunks = []  # Data Chunks are 16 octets
    data_chunks_crc = []
    # chunk_len = 18
    data_chunk_len = 16

    def show_data_chunks(self):
        for i in range(len(self.data_chunks)):
            print("\tData Chunk", i, "Len", len(self.data_chunks[i]), "CRC (", hex(struct.unpack('<H', self.data_chunks_crc[i])[0]), ")")

    def add_check_sum(self, chunk):
        checkSum = crc16DNP(chunk)
        print(f"ADD CRC \n chunk: {type(chunk)}:{chunk}\n, checkSum: {type(checkSum)}:{checkSum}")
        self.data_chunks.append(chunk)
        self.data_chunks_crc.append(checkSum)

    def post_dissect(self, s: bytes):
        print(f"s: {s}")
        return s
    
    def post_build(self, pkt, pay):
        if len(pkt) <= 8:
            return pkt

        dataLinkHeader = pkt[:8]
        dataLinkHeaderChecksum = crc16DNP(dataLinkHeader)  # use only the first 8 octets
        finalPkt = dataLinkHeader + dataLinkHeaderChecksum
        print(f"dataLinkHeader: {dataLinkHeader}")
        print(f"dataLinkHeaderChecksum: {dataLinkHeaderChecksum}")
        print(f"finalPkt: {finalPkt}")
        
        dnp3PKT = pkt[8:]
        cnk_len = self.data_chunk_len
        pay_len = len(pay)
        pkt_len = len(dnp3PKT)
        total = pkt_len + pay_len
        chunks = total // cnk_len  # chunk size
        last_chunk = total % cnk_len
        
        if last_chunk > 0:
            chunks += 1
        
        print(f"dnp3PKT: {dnp3PKT}")
        print(f"pay_len: {pay_len}")
        print(f"pkt_len: {pkt_len}")
        print(f"total: {total}")
        print(f"chunks: {chunks}")
        print(f"last_chunk: {last_chunk}")

        # if pay_len == 3 and self.control.DIR == MASTER:
        #     # No IIN in Application layer and empty Payload
        #     pay = pay + struct.pack('H', crc16DNP(pay))

        # if pay_len == 5 and self.control.DIR == OUTSTATION:
        #     # IIN in Application layer and empty Payload
        #     pay = pay + struct.pack('H', crc16DNP(pay))

        # if self.length is None:
        #     # Remove length , crc, start octets as part of length
        #     length = (len(dnp3PKT+pay) - ((chunks * 2) + 1 + 2 + 2))
        #     dnp3PKT = dnp3PKT[:2] + struct.pack('<B', length) + dnp3PKT[3:]
        
        self.data_chunks = []
        self.data_chunks_crc = []

        remaining_pay = pay_len
        print(f"pay_len: {pay_len}")
        print(f"chunks: {chunks}")
        for c in range(chunks):
            index = c * cnk_len  # data chunk
            print(
                f"c: {c}, cnk_len: {cnk_len}, index: {index}, dnp3PKT[index:]:{dnp3PKT[index:]}")

            if (remaining_pay < cnk_len) and (remaining_pay > 0):
                self.add_check_sum(dnp3PKT[index:])
                break  # should be the last chunk
            else:
                self.add_check_sum(dnp3PKT[index:index + cnk_len])
                remaining_pay -= cnk_len

        payload = bytearray()
        for chunk in range(len(self.data_chunks)):
            print(f"self.data_chunks[chunk]: {self.data_chunks[chunk]}")
            print(f"self.data_chunks_crc[chunk]: {self.data_chunks_crc[chunk]}")
            payload = payload + self.data_chunks[chunk] + self.data_chunks_crc[chunk]
        self.show_data_chunks()  # --DEBUGGING
        print(f"final: \n dnp3PKT: {dnp3PKT}, payload: {payload}, dnp3PKT+payload: {dnp3PKT+payload}")
        finalPkt += payload
        return finalPkt
        
    def guess_payload_class(self, payload):
        if len(payload) == 0:
            return Packet.guess_payload_class(self, payload)
        else:
            return TransportControl

if __name__ == 'dnp3_dissector':
    # Bind UDP packets on DNP3 port
    bind_layers(UDP, DNP3, dport=DNP3_PORT_NUMBER)
    bind_layers(UDP, DNP3, sport=DNP3_PORT_NUMBER)

    # Bind TCP packets on DNP3 port
    bind_layers(TCP, DNP3, dport=DNP3_PORT_NUMBER)
    bind_layers(TCP, DNP3, sport=DNP3_PORT_NUMBER)
