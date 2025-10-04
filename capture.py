
#capture.py

from scapy.all import sniff, rdpcap
from typing import Callable, Optional

def live_capture(interface: str, bpf: str, prn: Callable):
    sniff(iface=interface, filter=bpf, prn=prn, store=False)

def pcap_capture(pcap_file: str, prn: Callable, count: Optional[int]=None):
    for pkt in rdpcap(pcap_file, count=count):
        prn(pkt)