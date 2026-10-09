import pandas as pd 
from scapy.all import sniff, IP
from Backend.live_data.live_capture import extract_features

# Global DL Model reference (apna model load karne par isko assign karein)
dl_model = None

def dl_model_input (packet): 
    """
    Bridge function: Receives packet, extracts features, splits data to DL Model & Live Graph.
    """
    try:
        # 1. Packet Feature Extraction
        packet_features = extract_features(packet)
        
        if packet_features is not None:
            df_model_input = pd.DataFrame([packet_features])
            
            # Prediction Logic
            is_attack = False
            if dl_model is not None:
                prediction = dl_model.predict(df_model_input)
                is_attack = bool(prediction[0] > 0.5)

           
            # ROUTE B: Only 'tcp.len' ---> Live Graph (Socket.IO Emission)
   
            chart_value = packet_features.get("tcp.len", 0)
            src_ip = packet[IP].src if packet.haslayer(IP) else "127.0.0.1"

            # Socket payload structure
            
            event_name = 'threat_alert' if is_attack else 'normal_traffic'
            payload = {
                'chart_value': chart_value,
                'ip': src_ip,
                'is_attack': is_attack
            }
        
            return  df_model_input

            
    except Exception as e:
        print(f"Pipeline Processing Error: {e}")


   

def tcp_len_value(packet):

    try :
        packet_features = extract_features(packet)


        
        if packet_features is not None:   
            packet_features = extract_features(packet)
            chart_value = packet_features.get("tcp.len", 0)
            src_ip = packet[IP].src if packet.haslayer(IP) else "127.0.0.1"
            # print("tcp_len",chart_value)
            return chart_value 
    except Exception as e:
        print(f"Pipeline Processing Error: {e}")




    