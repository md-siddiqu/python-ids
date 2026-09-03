# ======================================================================
# Simple Intrusion Detection System (IDS) using Python and Scapy
# ======================================================================
# This script captures live network traffic and detects:
#   - SYN flood attacks (TCP SYN without ACK)
#   - ARP spoofing (IP-to-MAC changes)
#   - DNS spoofing (first-seen domain-to-IP mappings, alerts on changes)
#
# It prints alerts to the console and saves them to 'ids_log.txt'.
# ======================================================================

# ---------- Imports ----------
from scapy.all import *        # Import all Scapy functions for packet manipulation
import time                    # For timestamps in alerts

# ---------- Configuration ----------
# Choose the network interface to sniff on.
# Set to None to use the system's default interface.
INTERFACE = "eth1"             # Change to "wlan0" or "any" as needed

# List of IP addresses that are considered suspicious (manual blacklist)
SUSPICIOUS_IPS = ['192.168.1.10', '192.168.1.15']

# ---------- Global Data Structures ----------
# ARP table: maps IP address to MAC address to detect changes
arp_table = {}

# DNS cache: maps domain name to the first seen IP address
# We trust the first answer; any subsequent different IP triggers an alert
dns_cache = {}

# ---------- Helper Functions ----------
def log_alert(alert_message):
    """
    Append an alert message with a timestamp to the log file.
    """
    with open("ids_log.txt", "a") as log_file:   # Open file in append mode
        log_file.write(f"{time.ctime()}: {alert_message}\n")   # Write timestamp + alert

# ---------- Packet Callback (core analysis) ----------
def packet_callback(packet):
    """
    This function is called for every captured packet.
    It analyses the packet for suspicious patterns and raises alerts.
    """
    # --- Task 2: Print basic details for every packet ---
    # This satisfies the requirement to "print out basic details".
    # We use packet.summary() which gives a concise human-readable description.
    print(f"[PACKET] {packet.summary()}")

    try:
        # --- IP Layer Processing (for all IP-based traffic) ---
        if packet.haslayer(IP):
            ip_src = packet[IP].src          # Source IP address
            ip_dst = packet[IP].dst          # Destination IP address
            proto = packet.payload.name      # Protocol name (e.g., 'TCP', 'UDP')

            # Check if the source IP is in the manual blacklist
            if ip_src in SUSPICIOUS_IPS:
                alert = f"Suspicious source IP: {ip_src} -> {ip_dst} [{proto}]"
                print(f"[{time.ctime()}] ALERT: {alert}")
                log_alert(alert)

            # --- SYN Flood Detection (Task 3) ---
            # Look for TCP packets with only the SYN flag set (no ACK)
            if packet.haslayer(TCP) and packet[TCP].flags == "S":
                alert = f"Potential SYN flood from {ip_src} -> {ip_dst}"
                print(f"[{time.ctime()}] ALERT: {alert}")
                log_alert(alert)

        # --- ARP Layer Processing (Task 3) ---
        # Detect ARP spoofing: monitor ARP replies (op=2) for IP-MAC changes
        if packet.haslayer(ARP) and packet[ARP].op == 2:   # op=2 is ARP reply
            ip = packet[ARP].psrc          # IP address claimed in the reply
            mac = packet[ARP].hwsrc        # MAC address claimed

            # If we already have a mapping for this IP and the MAC differs -> spoofing
            if ip in arp_table and arp_table[ip] != mac:
                alert = f"ARP Spoofing Detected: IP {ip} is now at {mac} (was {arp_table[ip]})"
                print(f"[{time.ctime()}] ALERT: {alert}")
                log_alert(alert)

            # Update the ARP table with the latest mapping
            arp_table[ip] = mac

        # --- DNS Layer Processing (Task 3 - IMPROVED) ---
        # Detect DNS spoofing by caching the first response for each domain
        # and alerting if a different IP appears later.
        if packet.haslayer(DNS) and packet.haslayer(DNSRR):
            # We are only interested in DNS responses that contain an answer record
            # Note: DNSRR is the Answer Resource Record layer.
            # The query name is in DNSQR (Question Record)
            if packet.haslayer(DNSQR):
                query_name = packet[DNSQR].qname.decode()   # Domain name (e.g., "example.com.")
                # Get the answer IP (rdata) from the first DNSRR
                # (We take the first answer for simplicity; real-world may have multiple)
                answer_ip = packet[DNSRR].rdata

                # Check if this domain has been seen before
                if query_name in dns_cache:
                    # If the IP differs from the cached one, raise an alert
                    if dns_cache[query_name] != answer_ip:
                        alert = (f"DNS Spoofing possible: {query_name} resolved to "
                                 f"{answer_ip} (previously {dns_cache[query_name]})")
                        print(f"[{time.ctime()}] ALERT: {alert}")
                        log_alert(alert)
                else:
                    # First time seeing this domain; store the IP in cache
                    dns_cache[query_name] = answer_ip

                # Also log every DNS response for visibility (optional)
                # This can help in monitoring, but we may not want to flood logs
                # We'll print it as an INFO message, not an alert.
                info = f"DNS Response: {query_name} -> {answer_ip}"
                print(f"[{time.ctime()}] INFO: {info}")
                # (We do not log this to file to keep log focused on alerts)

    except Exception as e:
        # ---------- Error Handling (Task 5) ----------
        # Catch any exception during packet processing to prevent crashes.
        # Log the error and continue sniffing.
        error_msg = f"Packet processing failed: {e} (packet: {packet.summary()})"
        print(f"[ERROR] {error_msg}")
        log_alert(f"Exception: {error_msg}")

# ---------- Main Sniffing Function ----------
def sniff_traffic():
    """
    Start capturing live network traffic using Scapy's sniff().
    A filter is applied to reduce overhead:
        - TCP (for SYN flood)
        - ARP (for ARP spoofing)
        - UDP port 53 (for DNS)
    """
    print("[INFO] IDS is starting...")
    print(f"[INFO] Using interface: {INTERFACE if INTERFACE else 'default'}")
    print("[INFO] Press Ctrl+C to stop.")

    # Sniff with the specified interface, filter, and callback.
    # store=0 prevents storing packets in memory, improving performance.
    sniff(
        iface=INTERFACE,                # Use the configured interface
        filter="tcp or arp or udp port 53",   # Only relevant traffic
        prn=packet_callback,            # Process each packet with this function
        store=0                         # Do not store packets
    )

# ---------- Entry Point ----------
if __name__ == "__main__":
    try:
        sniff_traffic()                # Start monitoring
    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C (Task 5)
        print("\n[INFO] IDS terminated by user.")
        # Optionally, you can save the ARP table and DNS cache here if needed.
