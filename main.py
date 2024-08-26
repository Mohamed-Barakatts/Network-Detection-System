from scapy.all import sniff, IP, TCP
from datetime import datetime

# Track the number of packets
packet_count = 0

# Store unique local IP addresses of devices on the local network
connected_devices = set()


# Define a function to detect and log potential port scans and connected devices
def detect_port_scan(packet):
    global packet_count
    packet_count += 1

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else None
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Check if the source IP is within the local network range
        if src_ip.startswith("192.168."):
            connected_devices.add(src_ip)

        # Log packet information
        log_entry = f"{timestamp} - Packet #{packet_count}: From {src_ip} to port {dst_port} | Local Devices Connected: {len(connected_devices)}"
        print(log_entry)

        # Optionally, log to a file
        with open("network_log.txt", "a") as log_file:
            log_file.write(log_entry + "\n")


# Sniff the network interface
sniff(filter="ip", prn=detect_port_scan)
