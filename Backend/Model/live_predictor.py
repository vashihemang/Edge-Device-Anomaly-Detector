import os
import time
import logging
import warnings

# --- TensorFlow / oneDNN noise silence karna (TF import se pehle) ---
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
warnings.filterwarnings('ignore')
logging.getLogger('tensorflow').setLevel(logging.ERROR)
logging.getLogger('absl').setLevel(logging.ERROR)

import numpy as np
import joblib

try:
    import tensorflow as tf  # type: ignore[import-not-found]
    from tensorflow.keras.models import load_model  # type: ignore[import-not-found]
except ImportError as exc:
    raise RuntimeError("TensorFlow is required to load the model.") from exc

from scapy.all import ARP, IP, TCP, UDP, Raw

tf.get_logger().setLevel('ERROR')


# ---------------------------------------------------------------------
# 1. Keras 3 compatibility patch (Dl_Model.py se as-is)
# ---------------------------------------------------------------------
class PatchedDense(tf.keras.layers.Dense):
    @classmethod
    def from_config(cls, config):
        config.pop('quantization_config', None)
        return super().from_config(config)


# ---------------------------------------------------------------------
# 2. Model + scaler ek hi baar load honge (module import ke time)
#    Paths ko is file ke folder ke relative rakha hai — apne hisaab se
#    adjust kar lena agar model/scaler kisi aur folder me hai.
# ---------------------------------------------------------------------
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(_BASE_DIR, "Backend\Model\dnn_model_iot_security.h5")
SCALER_PATH = os.path.join(_BASE_DIR, "Backend\Model\scaler.pkl")

model = load_model(MODEL_PATH, custom_objects={'Dense': PatchedDense}, compile=False)
scaler = joblib.load(SCALER_PATH)

print("[+] DL model & scaler loaded successfully.")

# Order EXACTLY wahi jo training/scaler fit karte waqt use hua tha
FEATURE_ORDER = [
    'arp.opcode',
    'http.content_length',
    'tcp.ack',
    'tcp.connection.syn.tcpsynack',
    'tcp.dstport',
    'tcp.flags',
    'tcp.len',
    'udp.port',
    'udp.time_delta',
    'mqtt.len',
    'mqtt.msgtype',
    'mqtt.proto_len',
    'mbtcp.len',
]
# Dl_Model.py ke attack_features me 15 values thin (13 real + 2 padding)
PADDING = [0.0, 0.0]


# ---------------------------------------------------------------------
# 3. Live feature extraction state (live_capture.py se as-is, bas
#    module-private banaya hai taaki naam clash na ho)
# ---------------------------------------------------------------------
_last_1s_reset = time.time()
_syn_count_1s = 0
_synack_count_1s = 0
_live_packet_count = 0
_last_udp_time = None


def extract_features(pkt):
    """Ek raw scapy packet se 13 core features nikalta hai (dict me)."""
    global _last_1s_reset, _syn_count_1s, _synack_count_1s
    global _live_packet_count, _last_udp_time

    current_time = time.time()
    _live_packet_count += 1

    if current_time - _last_1s_reset >= 1.0:
        _syn_count_1s = 0
        _synack_count_1s = 0
        _last_1s_reset = current_time

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

    if pkt.haslayer(ARP):
        arp_opcode = pkt[ARP].op

    if pkt.haslayer(TCP):
        tcp_dstport = pkt[TCP].dport
        tcp_ack = pkt[TCP].ack
        tcp_flags = int(pkt[TCP].flags)

        if pkt.haslayer(IP):
            ip_total_len = pkt[IP].len
            ip_hdr_len = pkt[IP].ihl * 4
            tcp_hdr_len = pkt[TCP].dataofs * 4
            tcp_len = max(0, ip_total_len - (ip_hdr_len + tcp_hdr_len))
        else:
            tcp_len = len(pkt[TCP].payload)

        flags = pkt[TCP].flags
        if flags == 'S' or flags == 0x02:
            _syn_count_1s += 1
        elif flags == 'SA' or flags == 0x12:
            _synack_count_1s += 1

        if _synack_count_1s > 0:
            tcp_connection_syn_tcpsynack = _syn_count_1s / _synack_count_1s
        else:
            tcp_connection_syn_tcpsynack = float(_syn_count_1s)

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)
            if b"HTTP/" in payload or b"POST" in payload or b"GET" in payload:
                for line in payload.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        try:
                            http_content_length = int(line.split(b":")[1].strip())
                        except ValueError:
                            pass

        if pkt[TCP].dport in [1883, 8883] or pkt[TCP].sport in [1883, 8883]:
            if pkt.haslayer(Raw):
                mqtt_raw = bytes(pkt[Raw].load)
                if len(mqtt_raw) >= 2:
                    mqtt_msgtype = (mqtt_raw[0] & 0xF0) >> 4
                    mqtt_len = mqtt_raw[1]
                    if mqtt_msgtype == 1 and len(mqtt_raw) >= 8:
                        mqtt_proto_len = (mqtt_raw[2] << 8) + mqtt_raw[3]

        if pkt[TCP].dport == 502 or pkt[TCP].sport == 502:
            if pkt.haslayer(Raw):
                mbtcp_raw = bytes(pkt[Raw].load)
                if len(mbtcp_raw) >= 6:
                    mbtcp_len = (mbtcp_raw[4] << 8) + mbtcp_raw[5]

    if pkt.haslayer(UDP):
        udp_port = pkt[UDP].dport
        if _last_udp_time is not None:
            udp_time_delta = current_time - _last_udp_time
        _last_udp_time = current_time

    return {
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
        'mbtcp.len': mbtcp_len,
    }


def get_and_reset_packet_count():
    global _live_packet_count
    count = _live_packet_count
    _live_packet_count = 0
    return count


# ---------------------------------------------------------------------
# 4. Feature dict -> scaled vector -> DL prediction
# ---------------------------------------------------------------------
def _feature_dict_to_vector(feature_dict):
    row = [feature_dict[key] for key in FEATURE_ORDER] + PADDING
    return np.array([row], dtype=float)


def predict(feature_dict):
    """
    Ek feature dict ko scaler + DL model se pass karta hai.
    Returns: (label, probability) -> label 'ATTACK' ya 'NORMAL'.
    """
    vector = _feature_dict_to_vector(feature_dict)
    scaled = scaler.transform(vector)
    prediction = model.predict(scaled, verbose=0)
    probability = float(prediction[0][0])
    label = "ATTACK" if probability > 0.5 else "NORMAL"
    return label, probability


def predict_from_packet(pkt):
    """
    Ek raw scapy packet se features nikal ke predict karta hai, aur saath
    me packet ka source IP bhi return karta hai (dashboard ke Threat Table
    me device/IP dikhane ke liye).
    Returns: (label, probability, src_ip)
    """
    features = extract_features(pkt)
    label, probability = predict(features)

    src_ip = None
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
    elif pkt.haslayer(ARP):
        src_ip = pkt[ARP].psrc

    return label, probability



# 5. DEMO/TEST INJECTOR — thodi-thodi der me ek synthetic "attack-jaisa"

import random

def make_synthetic_attack_features():
    """
    SYN-flood jaisa dikhne wala synthetic feature dict banata hai.
    PUBLIC function hai — main.py isse import karke seedha model ko
    call kar sakta hai (button-triggered demo attacks ke liye), taaki
    red line ("Threat Level") bhi genuinely DL model ke output se aaye,
    random number se nahi.
    """
    return {
        'arp.opcode': 0,
        'http.content_length': 0,
        'tcp.ack': 0,
        'tcp.connection.syn.tcpsynack': round(random.uniform(5, 20), 2),
        'tcp.dstport': random.choice([80, 443, 8080]),
        'tcp.flags': 2,          # SYN flag only
        'tcp.len': random.randint(40000, 65000),
        'udp.port': 0,
        'udp.time_delta': 0.0001,
        'mqtt.len': 0,
        'mqtt.msgtype': 0,
        'mqtt.proto_len': 0,
        'mbtcp.len': 0,
    }


# Purana naam bhi kaam kare, agar kahin reference ho
_make_synthetic_attack_features = make_synthetic_attack_features


def _make_synthetic_src_ip():
    """Demo ke liye ek random-looking external IP banata hai."""
    return f"203.0.113.{random.randint(2, 250)}"


def start_periodic_attack_simulation(min_interval=15, max_interval=40, on_result=None):
    """
    Background daemon thread start karta hai jo har ~min_interval se
    max_interval second ke beech ek baar synthetic attack feature vector
    banata hai, use ASLI model se predict karwata hai, aur result print
    karta hai.

    on_result: optional callback(label, probability, simulated, src_ip) —
    isse main.py se socketio.emit bhi kiya ja sakta hai.
    """
    import threading

    def _loop():
        while True:
            time.sleep(random.uniform(min_interval, max_interval))
            synthetic = make_synthetic_attack_features()
            label, probability = predict(synthetic)
            src_ip = _make_synthetic_src_ip()
            print(f"[SIMULATED] [{'🚨' if label == 'ATTACK' else '✓'}] "
                  f"{label} | Prob: {probability * 100:.2f}% | IP: {src_ip}")
            if on_result:
                try:
                    on_result(label, probability, True, src_ip)  # True = simulated
                except Exception as e:
                    print(f"[!] on_result callback error: {e}")

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t