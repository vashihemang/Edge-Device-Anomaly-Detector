import time
import pandas as pd 
from scapy.all import ARP, IP, TCP, UDP, Raw

# Global State Variables
last_1s_reset = time.time()
syn_count_1s = 0
synack_count_1s = 0
live_packet_count = 0 
last_udp_time = None

def extract_features(pkt):
    """
    Extracts 13 core packet features from a raw Scapy packet.
    Returns a dictionary of raw features.
    """
    global last_1s_reset, syn_count_1s, synack_count_1s, live_packet_count, last_udp_time
    
    current_time = time.time()
    live_packet_count += 1

    # Reset 1-second interval counters
    if current_time - last_1s_reset >= 1.0:
        syn_count_1s = 0
        synack_count_1s = 0
        last_1s_reset = current_time

    # Initialize feature vector defaults
    arp_opcode = 0
    http_content_length = 0
    tcp_ack = 0
    tcp_connection_syn_tcpsynack = 0.0
    tcp_dstport = 0
    tcp_flags = 0
    tcp_len = 0
    udp_port = 0
    udp_time_delta = 0.0
    mqtt_len = 0
    mqtt_msgtype = 0
    mqtt_proto_len = 0
    mbtcp_len = 0
    
    # 1. ARP Layer
    if pkt.haslayer(ARP):
        arp_opcode = pkt[ARP].op

    # 2. TCP Layer & High-Level Protocols
    if pkt.haslayer(TCP):
        tcp_dstport = pkt[TCP].dport
        tcp_ack = pkt[TCP].ack
        tcp_flags = int(pkt[TCP].flags)
        
        # Calculate TCP payload size
        if pkt.haslayer(IP):
            ip_total_len = pkt[IP].len
            ip_hdr_len = pkt[IP].ihl * 4
            tcp_hdr_len = pkt[TCP].dataofs * 4
            tcp_len = max(0, ip_total_len - (ip_hdr_len + tcp_hdr_len))
        else:
            tcp_len = len(pkt[TCP].payload)

        # SYN vs SYN-ACK tracking
        flags = pkt[TCP].flags
        if flags == 'S' or flags == 0x02:
            syn_count_1s += 1
        elif flags == 'SA' or flags == 0x12:
            synack_count_1s += 1
            
        if synack_count_1s > 0:
            tcp_connection_syn_tcpsynack = syn_count_1s / synack_count_1s
        else:
            tcp_connection_syn_tcpsynack = float(syn_count_1s)

        # HTTP Extraction
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if b"HTTP/" in payload or b"POST" in payload or b"GET" in payload:
                for line in payload.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        try:
                            http_content_length = int(line.split(b":")[1].strip())
                        except ValueError:
                            pass

        # MQTT Extraction
        if pkt[TCP].dport in [1883, 8883] or pkt[TCP].sport in [1883, 8883]:
            if pkt.haslayer(Raw):
                mqtt_raw = bytes(pkt[Raw].load)
                if len(mqtt_raw) >= 2:
                    mqtt_msgtype = (mqtt_raw[0] & 0xF0) >> 4
                    mqtt_len = mqtt_raw[1]
                    if mqtt_msgtype == 1 and len(mqtt_raw) >= 8:
                        mqtt_proto_len = (mqtt_raw[2] << 8) + mqtt_raw[3]

        # Modbus TCP Extraction
        if pkt[TCP].dport == 502 or pkt[TCP].sport == 502:
            if pkt.haslayer(Raw):
                mbtcp_raw = bytes(pkt[Raw].load)
                if len(mbtcp_raw) >= 6:
                    mbtcp_len = (mbtcp_raw[4] << 8) + mbtcp_raw[5]

    # 3. UDP Layer & Delta
    if pkt.haslayer(UDP):
        udp_port = pkt[UDP].dport
        if last_udp_time is not None:
            udp_time_delta = current_time - last_udp_time
        last_udp_time = current_time

    # Complete 13 Feature Vector Dictionary
    feature_dict = {
        'arp.opcode': arp_opcode,
        'http.content_length': http_content_length,
        'tcp.ack': tcp_ack,
        'tcp.connection.syn.tcpsynack': tcp_connection_syn_tcpsynack,
        'tcp.dstport': tcp_dstport,
        'tcp.flags': tcp_flags,
        'tcp.len': tcp_len,
        'udp.port': udp_port,
        'udp.time_delta': udp_time_delta,
        'mqtt.len': mqtt_len,
        'mqtt.msgtype': mqtt_msgtype,
        'mqtt.proto_len': mqtt_proto_len,
        'mbtcp.len': mbtcp_len
    }

    return feature_dict

def get_and_reset_packet_count():
    global live_packet_count
    count = live_packet_count
    live_packet_count = 0
    return count