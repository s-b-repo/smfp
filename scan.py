#!/usr/bin/env python3
import random
import sys
import os
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, sr1, conf

conf.verb = 0  # Suppress Scapy output

def is_private(ip):
    octets = list(map(int, ip.split('.')))
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    if octets[0] >= 224:
        return True
    return False

def generate_public_ip():
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(0, 255)
        ip = f"{a}.{b}.{c}.{d}"
        if not is_private(ip):
            return ip

def check_ports(ip):
    open_ports = []
    try:
        # Check FTP (21)
        ftp_pkt = IP(dst=ip)/TCP(dport=21, flags='S')
        ftp_resp = sr1(ftp_pkt, timeout=1, verbose=0)
        if ftp_resp and ftp_resp.haslayer(TCP):
            if ftp_resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                open_ports.append(21)
                # Send RST to close connection
                sr1(IP(dst=ip)/TCP(dport=21, flags='R'), timeout=1, verbose=0)
        
        # Check SMTP (25)
        smtp_pkt = IP(dst=ip)/TCP(dport=25, flags='S')
        smtp_resp = sr1(smtp_pkt, timeout=1, verbose=0)
        if smtp_resp and smtp_resp.haslayer(TCP):
            if smtp_resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                open_ports.append(25)
                sr1(IP(dst=ip)/TCP(dport=25, flags='R'), timeout=1, verbose=0)
    except:
        pass
    return ip, open_ports

def handle_result(future):
    try:
        ip, open_ports = future.result()
        if 21 in open_ports and 25 in open_ports:
            print(f"[+] Valid target found: {ip}")
            with open("results.txt", "a") as f:
                f.write(f"{ip}\n")
    except:
        pass

def main():
    if os.geteuid() != 0:
        print("Root privileges required for stealth scanning. Use sudo.")
        sys.exit(1)
    
    print("Starting stealthy SMTP/FTP scanner...")
    print("Press Ctrl+C to stop and save results\n")
    
    with ThreadPoolExecutor(max_workers=200) as executor:
        try:
            while True:
                ip = generate_public_ip()
                future = executor.submit(check_ports, ip)
                future.add_done_callback(handle_result)
        except KeyboardInterrupt:
            print("\nTermination signal received. Waiting for pending scans...")
            executor.shutdown(wait=True)
            print("Scan stopped. Results saved to results.txt")

if __name__ == "__main__":
    main()
