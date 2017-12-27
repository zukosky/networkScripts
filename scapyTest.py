import scapy
from scapy.all import sniff

def dummyHandler(packet):

	return
sniff(filter='ip',prn=dummyHandler,store=0)
