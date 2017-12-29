import scapy
from scapy.all import *


def dummyHandler(packet):
    return


# The following will sniff 10  packats and print out a summary when it finds them
a = sniff(count=5)
a.nsummary()
a[0].show()
print(a[0])
a[1].show()
print(a[1])
a[2].show()
print(a[2])

# This will send off an ICMP packet to my VPS
send(IP(dst="45.55.160.23") / ICMP())
# THis will send a layer 2 packet
sendp(Ether() / IP(dst="45.55.160.23", ttl=(1, 4)))
