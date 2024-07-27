from scapy.all import sniff, IP, TCP

# Define rules
ALLOWED_IPS = ["192.168.1.2", "192.168.1.3"]
BLOCKED_PORTS = [80, 443]

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        if ip_src not in ALLOWED_IPS:
            print(f"Blocked IP: {ip_src}")
            return
        
        if TCP in packet:
            tcp_dport = packet[TCP].dport
            if tcp_dport in BLOCKED_PORTS:
                print(f"Blocked Port: {tcp_dport}")
                return

        print(f"Allowed Packet: {packet.summary()}")

# Sniff packets
sniff(filter="ip", prn=packet_callback, store=0)
