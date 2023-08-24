from scapy.all import *

info = '''
+==================================+
'''

print(info)

def network(ptk):
    if ptk.haslayer(TCP):
        print(ptk)
        print('TCP packet!')
        print('_____________')
        if ptk.haslayer(Raw):
            print('Data Size:', len(ptk[Raw].load))
            print('Data:', ptk[Raw].load)
        src_ip = ptk[IP].src
        dst_ip = ptk[IP].dst
        src_port = ptk.sport
        dst_port = ptk.dport
        print('Source IP : ' , src_ip )
        print('Destanion IP : ' , dst_ip )
        print('SEND PORT is :'+ str(src_port))
        print('Destanion PORT is :'+ str(dst_port))
    if ptk.haslayer(UDP):
        print(ptk)
        print('UDP packet!')
        print('_____________')
        if ptk.haslayer(Raw):
            print('Data Size:', len(ptk[Raw].load))
            print('Data:', ptk[Raw].load)
        src_ip = ptk[IP].src
        dst_ip = ptk[IP].dst
        src_port = ptk.sport
        dst_port = ptk.dport
        print('Source IP : ' , src_ip )
        print('Destanion IP : ' , dst_ip )
        print('SEND PORT is :'+ str(src_port))
        print('Destanion PORT is :'+ str(dst_port))
    if ptk.haslayer(ICMP):
        print(ptk)
        print('ICMP packet!')
        print('_____________')
        if ptk.haslayer(Raw):
            print('Data Size:', len(ptk[Raw].load))
            print('Data:', ptk[Raw].load)
        src_ip = ptk[IP].src
        dst_ip = ptk[IP].dst
        src_port = ptk.sport
        dst_port = ptk.dport
        print('Source IP : ' , src_ip )
        print('Destanion IP : ' , dst_ip )
        print('SEND PORT is :'+ str(sport))
        print('Destanion PORT is :'+ str(dport))    

sniff(iface='Ethernet', prn=network)
