import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    print("------------")
    print("----- Sniffer Has Started -------")
    print("------------")
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode()
        print("[+] Host:", host)
        if packet.haslayer(scapy.Raw):
            request = packet[scapy.Raw].load.decode(errors='ignore')
            print("[*_*] Raw Data:", request)

sniff("Ethernet")  # Replace "eth0" with your actual interface name

