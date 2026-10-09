from Backend.live_data.extract_data import tcp_len_value
from scapy.all import sniff



def start_sniffer(interface="Realtek RTL8822CE 802.11ac PCIe Adapter"):
    print(f"\n[+] Sniffer initialized on {interface}...")
    try:
        # prn me ab humara process_packet function jayega
        sniff(iface=interface, prn=tcp_len_value, store=0)
    except Exception as e:
        print(f"Sniffer execution stopped due to error: {e}")

if __name__ == '__main__':
    start_sniffer()