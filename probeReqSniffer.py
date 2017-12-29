from scapy.all import *
import time
import datetime
################################################################
# beaconSniffer.py
#
# This script will take a WLAN network card in Monitor mode and
# list all of the unique MAC address - Probe combinations
#
#################################################################
mac_list = []
mac_count = []
TAB_1 = "\t"
def PacketHandler(pkt) :
print("num"+TAB_1+"Time"+TAB_1+"MAC"+TAB_1+"ESSID")
  if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 4 :
			#pkt.summary()
			#Print if the combined MAC+AP
			if len(pkt.info) >0 and pkt.addr2 not in mac_list :
				mac_list.append(pkt.addr2)
				print "%s\t%s\t%s\t%s" %(str(len(mac_list)),str(datetime.datetime.now().time())[0:8],pkt.addr2, pkt.info)
#				print str(len(mac_list)) + "  "+str(datetime.datetime.now().time())[0:8] + " DEVICE MAC: %s PROBING SSID: %s " %(pkt.addr2, pkt.info)
#				print str(len(mac_list)) + "  "+str(datetime.datetime.now().time())[0:8] + " DEVICE MAC: %s PROBING SSID: %s " %(pkt.addr2, pkt.info)
#Scapy by default stores all packets.  Need store=0.
sniff(iface="wlan0", prn = PacketHandler,store=0)