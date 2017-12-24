import sys
from scapy.all import *


p=sr1(IP(dst=sys.argv[1])/ICMP())
if p:
    p.show()