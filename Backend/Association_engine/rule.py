import threading
import time as _time
from collections import deque

import pandas as pd
from mlxtend.frequent_patterns import fpgrowth, association_rules
from mlxtend.preprocessing import TransactionEncoder


# ---------------------------------------------------------------------
# 1. Discretization — numeric features ko categorical "items" me todna
#    (Association rule mining continuous numbers par kaam nahi karti)
# ---------------------------------------------------------------------
def discretize_features(feature_dict):
    """Feature dict (numeric) ko categorical item-list me convert karta hai."""
    items = []

    tcp_len = feature_dict.get('tcp.len', 0)
    if tcp_len == 0:
        items.append('tcp_len=zero')
    elif tcp_len < 500:
        items.append('tcp_len=small')
    elif tcp_len < 5000:
        items.append('tcp_len=medium')
    else:
        items.append('tcp_len=large')

    dstport = feature_dict.get('tcp.dstport', 0)
    if dstport in (80, 443, 8080):
        items.append('port=web')
    elif dstport in (1883, 8883):
        items.append('port=mqtt')
    elif dstport == 502:
        items.append('port=modbus')
    elif dstport == 0:
        items.append('port=none')
    else:
        items.append('port=other')

    flags = feature_dict.get('tcp.flags', 0)
    if flags == 2:
        items.append('flags=syn_only')
    elif flags == 18:
        items.append('flags=syn_ack')
    elif flags == 0:
        items.append('flags=none')
    else:
        items.append('flags=other')

    syn_ratio = feature_dict.get('tcp.connection.syn.tcpsynack', 0)
    if syn_ratio > 5:
        items.append('syn_ratio=high')
    elif syn_ratio > 1:
        items.append('syn_ratio=medium')
    else:
        items.append('syn_ratio=low')

    udp_delta = feature_dict.get('udp.time_delta', 0)
    if 0 < udp_delta < 0.01:
        items.append('udp_rate=very_fast')
    elif udp_delta > 0:
        items.append('udp_rate=normal')

    if feature_dict.get('arp.opcode', 0) != 0:
        items.append('arp=active')

    return items


# ---------------------------------------------------------------------
# 2. Transaction log — sirf ATTACK-flagged traffic yahan store hota hai
# ---------------------------------------------------------------------
MAX_TRANSACTIONS = 20         # kitni recent attack-transactions yaad rakhein
MIN_TRANSACTIONS_TO_MINE = 120 # itni jama hone tak rules generate nahi honge

_transactions = deque(maxlen=MAX_TRANSACTIONS)
_rules_df = pd.DataFrame()
_lock = threading.Lock()


def log_attack_transaction(feature_dict):
    """Jab model ATTACK bole, uske discretized items yahan store karo."""
    items = discretize_features(feature_dict)
    with _lock:
        _transactions.append(items)


def mine_rules(min_support=0.1, min_confidence=0.6):
    """
    FP-Growth chala ke frequent itemsets + association rules generate karta hai.
    Thoda costly hai — isliye periodically (background thread se) call hota
    hai, har packet par nahi.
    """
    global _rules_df

    with _lock:
        if len(_transactions) < MIN_TRANSACTIONS_TO_MINE:
            return _rules_df
        snapshot = list(_transactions)

    te = TransactionEncoder()
    te_array = te.fit(snapshot).transform(snapshot)
    df = pd.DataFrame(te_array, columns=te.columns_)

    frequent_itemsets = fpgrowth(df, min_support=min_support, use_colnames=True)
    if frequent_itemsets.empty:
        return _rules_df

    rules = association_rules(frequent_itemsets, metric="confidence", min_threshold=min_confidence)
    rules = rules.sort_values(by=['confidence', 'lift'], ascending=False)

    with _lock:
        _rules_df = rules

    print(f"[+] Association rules updated: {len(rules)} rules mined "
          f"from {len(snapshot)} attack transactions.")
    return _rules_df


def match_rules(feature_dict):
    """
    Naye incoming traffic ke items ko known attack-rules se match karta hai.
    Returns: (matched: bool, confidence: float 0-1, lift: float)
    """
    with _lock:
        rules = _rules_df

    if rules.empty:
        return False, 0.0, 0.0

    items = set(discretize_features(feature_dict))
    best_confidence = 0.0
    best_lift = 0.0
    matched = False

    for _, rule in rules.iterrows():
        antecedent = set(rule['antecedents'])
        if antecedent.issubset(items):
            matched = True
            if rule['confidence'] > best_confidence:
                best_confidence = float(rule['confidence'])
                best_lift = float(rule['lift'])

    return matched, best_confidence, best_lift


def start_periodic_mining(interval_seconds):
    """Background thread — har interval par rules ko refresh karta rahega."""
    def _loop():
        while True:
            _time.sleep(interval_seconds)
            try:
                mine_rules()
            except Exception as e:
                print(f"[!] Rule mining error: {e}")

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------
# 3. Risk Engine — DL model output + Association Rules ko combine karta hai
# ---------------------------------------------------------------------
DL_WEIGHT = 0.7      # final risk score me DL model ka weight
RULE_WEIGHT = 0.3    # final risk score me rule-match confidence ka weight
RISK_THRESHOLD = 0.5


def compute_risk(dl_label, dl_probability, feature_dict):
    """
    Final decision:
      combined_risk = 0.7 * DL_probability + 0.3 * rule_confidence
                       (agar koi rule match hua ho, warna sirf DL probability)

    Returns dict:
      {
        'label': 'ATTACK'/'NORMAL',
        'risk_score': 0-100,        <- ye final combined score hai
        'dl_probability': 0-100,    <- sirf DL model ka number
        'rule_matched': bool,
        'rule_confidence': 0-100,
      }
    """
    rule_matched, rule_confidence, rule_lift = match_rules(feature_dict)

    if rule_matched:
        combined = (DL_WEIGHT * dl_probability) + (RULE_WEIGHT * rule_confidence)
    else:
        combined = dl_probability

    final_label = "ATTACK" if combined > RISK_THRESHOLD else dl_label

    # DL ne jise ATTACK bola, wo future rule-mining ke liye log ho jata hai
    if dl_label == "ATTACK":
        log_attack_transaction(feature_dict)

    return {
        'label': final_label,
        'risk_score': round(combined * 100, 2),
        'dl_probability': round(dl_probability * 100, 2),
        'rule_matched': rule_matched,
        'rule_confidence': round(rule_confidence * 100, 2),
    }