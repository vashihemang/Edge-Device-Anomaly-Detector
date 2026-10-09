from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO
from scapy.all import sniff
import threading
import sqlite3
import os
import random
import time
import socket
import webbrowser
from threading import Timer


# DL model 

try:
    from Backend.Model.live_predictor import extract_features, predict, make_synthetic_attack_features
    DL_READY = True
    print("[+] live_predictor loaded — real DL predictions ON.")
except Exception as e:
    print(f"Warning: live_predictor load nahi hua ({e}). Fallback mode me chal raha hai.")
    DL_READY = False
    def extract_features(packet):
        return {}
    def predict(feature_dict):
        return "NORMAL", 0.0
    def make_synthetic_attack_features():
        return {}


# Association Rule Mining FP-Growth + Risk Engine 

try:
    from Backend.Association_engine.rule import compute_risk, start_periodic_mining, get_engine_status
    RULES_READY = True
    print("[+] association_engine loaded — FP-Growth rules ON.")
except Exception as e:
    print(f"Warning: association_engine load nahi hua ({e}). Sirf DL model use hoga.")
    RULES_READY = False
    def compute_risk(dl_label, dl_probability, feature_dict):
        return {
            'label': dl_label,
            'risk_score': round(dl_probability * 100, 2),
            'dl_probability': round(dl_probability * 100, 2),
            'rule_matched': False,
            'rule_confidence': 0.0,
        }
    # def start_periodic_mining(interval_seconds=120):
    #     pass
    def get_engine_status():
        return {'error': 'association_engine not loaded', 'transactions_logged': 0,
                'transactions_needed': 0, 'rules_generated': 0}

app = Flask(__name__, template_folder="Frontend/template", static_folder="Frontend/static")
app.secret_key = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*")

traffic_stats = {
    'packet_count': 0,
    'total_bytes': 0,
    'attacks_blocked': 0,
    'anomalies': 0,
    'rule_matches': 0
}

DB_DIR = os.path.join('Backend', 'database')
os.makedirs(DB_DIR, exist_ok=True)
DB_NAME = os.path.join(DB_DIR, 'database.db')


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute(
            "create table if not exists users "
            "(id integer primary key autoincrement, username text unique not null, password text not null)"
        )
        conn.commit()

init_db()


# ROUTES (Authentication & Dashboard)

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required.'}), 400

    hashed_password = generate_password_hash(password)

    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("insert into users (username, password) values (?, ?)", (username, hashed_password))
            conn.commit()
        return jsonify({'success': True, 'message': 'Registration successful! You can now log in.'})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Username already exists.'}), 409
    except Exception:
        return jsonify({'success': False, 'message': 'An error occurred server-side.'}), 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required.'}), 400

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("select * from users where username = ?", (username,))
        user = cursor.fetchone()

    if user and check_password_hash(user['password'], password):
        session['user'] = user['username']
        return jsonify({'success': True, 'message': 'Login successful!'})
    else:
        return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401


@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html', username=session['user'])


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))



# ATTACK SIMULATION — button-controlled

attack_simulation_active = False


@app.route('/toggle_attack', methods=['POST'])
def toggle_attack():
    global attack_simulation_active
    attack_simulation_active = not attack_simulation_active
    state = "STARTED" if attack_simulation_active else "STOPPED"
    print(f"[*] Attack simulation {state} (via dashboard button)")
    return jsonify({'success': True, 'active': attack_simulation_active})


@app.route('/attack_status')
def attack_status():
    return jsonify({'active': attack_simulation_active})


@app.route('/debug/rules_status')
def debug_rules_status():
    """
    Browser me http://127.0.0.1:5000/debug/rules_status kholke check karo:
    - abhi tak kitne ATTACK-transactions log ho chuke hain
    - kitne aur chahiye mining shuru hone ke liye
    - abhi tak kitne rules ban chuke hain
    """
    return jsonify(get_engine_status())



# NETWORK SNIFFER & SOCKET EMITTERS

SERVER_START_TIME = 0

def process_packet(packet):
    """
    Har real packet ka pipeline:
        packet -> extract_features -> DL model (predict) -> Risk Engine
        (FP-Growth rule match + weighted combine) -> final decision
    """
    global traffic_stats, SERVER_START_TIME

    traffic_stats['packet_count'] += 1
    traffic_stats['total_bytes'] += len(packet)

    # Server start hote hi 25 second tak sirf traffic count hoga
    if SERVER_START_TIME == 0 or (time.time() - SERVER_START_TIME) < 25:
        return

    try:
        features = extract_features(packet)
        dl_label, dl_probability = predict(features)          # 1) DL model
        risk = compute_risk(dl_label, dl_probability, features)  # 2) Risk Engine (rules + combine)

        if risk['label'] == "ATTACK":
            traffic_stats['attacks_blocked'] += 1
            traffic_stats['anomalies'] += 1
            if risk['rule_matched']:
                traffic_stats['rule_matches'] += 1

            socketio.emit('attack_prediction', {
                'label': 'ATTACK',
                'probability': risk['risk_score'],           # final combined risk score
                'dl_probability': risk['dl_probability'],     # sirf DL model ka number
                'rule_matched': risk['rule_matched'],
                'rule_confidence': risk['rule_confidence'],
                'attacks_blocked': traffic_stats['attacks_blocked'],
                'anomalies': traffic_stats['anomalies'],
                'rule_matches': traffic_stats['rule_matches'],
                'time': time.strftime("%H:%M:%S"),
                'simulated': False
            })
    except Exception as e:
        print(f"[!] Prediction error: {e}")


def generate_traffic():
    """Har 1 second me Live Traffic (blue line) ka data bhejta hai."""
    while True:
        socketio.sleep(1)
        chart_val = traffic_stats['packet_count']
        socketio.emit('normal_traffic', {'chart_value': chart_val})
        traffic_stats['packet_count'] = 0
        traffic_stats['total_bytes'] = 0


def simulate_threat_attacks():
    """
    Button-controlled demo loop — synthetic input bhi USI pipeline se guzarta
    hai: DL model -> Risk Engine (FP-Growth rules + combine).
    """
    while True:
        if attack_simulation_active:
            synthetic_features = make_synthetic_attack_features()
            dl_label, dl_probability = predict(synthetic_features)       # 1) DL model
            risk = compute_risk(dl_label, dl_probability, synthetic_features)  # 2) Risk Engine

            traffic_stats['attacks_blocked'] += 1
            traffic_stats['anomalies'] += 1
            if risk['rule_matched']:
                traffic_stats['rule_matches'] += 1

            print(f"[{'🚨' if risk['label'] == 'ATTACK' else '✓'}] Simulated -> "
                  f"DL={risk['dl_probability']}% | Rule={'match' if risk['rule_matched'] else 'no-match'} "
                  f"({risk['rule_confidence']}%) | Final risk={risk['risk_score']}%")

            socketio.emit('attack_prediction', {
                'label': risk['label'],
                'probability': risk['risk_score'],
                'dl_probability': risk['dl_probability'],
                'rule_matched': risk['rule_matched'],
                'rule_confidence': risk['rule_confidence'],
                'attacks_blocked': traffic_stats['attacks_blocked'],
                'anomalies': traffic_stats['anomalies'],
                'rule_matches': traffic_stats['rule_matches'],
                'time': time.strftime("%H:%M:%S"),
                'simulated': True
            })
            socketio.sleep(random.randint(3,6))
        else:
            socketio.sleep(1)


def start_tcp_len_sniffer(interface="Realtek RTL8822CE 802.11ac PCIe Adapter"):
    print(f"\n[+] Sniffer initialized on {interface}...")
    try:
        sniff(iface=interface, prn=process_packet, store=0)
    except Exception as e:
        print(f"Sniffer execution stopped due to error: {e}")



# INTERNET CONNECTION CHECKER

def check_internet():
    print("[*] Checking Internet Connection...")
    while True:
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            print("[+] Internet / Wi-Fi is Connected! Starting services...")
            break
        except OSError:
            print("[-] No Internet connection. Waiting for network... Retrying in 5 seconds.")
            time.sleep(5)


def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")


if __name__ == '__main__':
    check_internet()

    SERVER_START_TIME = time.time()

    sniffer_thread = threading.Thread(target=start_tcp_len_sniffer, daemon=True)
    sniffer_thread.start()

    socketio.start_background_task(generate_traffic)
    socketio.start_background_task(simulate_threat_attacks)

    # FP-Growth rules ko har 2 minute me refresh karta rahega
    # jaise-jaise attack transactions jama hote hain, rules better hote jaate hain
    start_periodic_mining(interval_seconds=30)

    Timer(1.5, open_browser).start()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False, log_output=False)