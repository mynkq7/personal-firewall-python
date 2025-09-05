from scapy.all import sniff
import logging

# Setup logging for blocked packets
logging.basicConfig(filename="firewall.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Example: block traffic from a specific IP
blocked_ip = "192.168.1.100"   # change this to any IP you want to block

def packet_callback(packet):
    try:
        src_ip = packet[0][1].src
        dst_ip = packet[0][1].dst
        proto = packet[0][1].proto

        if src_ip == blocked_ip:
            logging.info(f"Blocked packet from {src_ip} to {dst_ip} (Protocol: {proto})")
            print(f"🚫 Blocked packet from {src_ip} to {dst_ip}")
        else:
            print(f"✅ Allowed packet from {src_ip} to {dst_ip}")
    except Exception as e:
        pass  # ignore errors for malformed packets

print("🔥 Personal Firewall Started...")
print(f"Blocking traffic from {blocked_ip}")
sniff(prn=packet_callback, store=0)
