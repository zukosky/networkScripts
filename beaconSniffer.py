from scapy.all import *
from netutils import *
################################################################
# beaconSniffer.py
#
# This script will take a WLAN network card in Monitor mode and
# list all of the unique dot11 beacons and corresponding MAC addresses
#
#################################################################
ap_list = []
ESSID_list = []
power_list=[]
headerFormatString ="{:<4s} {:^18s} {:^8s} {:<60s} "
formatString ="{:<4d} {:<18s} {:<8d} {:<60s} "

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11) :
		if pkt.type == 0 and pkt.subtype == 8:
			if pkt.addr2 not in ap_list :
				ap_list.append(pkt.addr2)
				#pkt.info is a byte array. Need to decode to get a string
				ESSID_list.append((pkt.info.decode("utf-8")))
				#pkt.show()
				print("-(256 - ord(pkt[3:3])")
				#rssi = -(256 - ord(pkt[3:3]))
				print("-(256 - ord(pkt[11:11])")
				#rssi = -(256 - ord(pkt[11:11]))
				#print(rssi)
				#try:
				#	channel = int(ord[Dot11Elt:3].info)
				#except:
				#	channel=0
				#print(channel)
				try:
					extra = pkt.notdecoded
					print(extra)
					rssi = -(256 - ord(extra[-2:-1]))
				except:
					rssi = -100
				power_list.append(rssi)	
#				print(pkt)			
os.system('clear')
for channel_c in range(1,3):
	print("Sniffing channel %d..." %channel_c,end='\r')
	set_wifi_channel(channel_c)
	sniff(iface="wlan0", prn = PacketHandler, count=40,filter="type mgt subtype beacon")
print (headerFormatString.format ("num","MAC","Power","ESSID"))
for nindex in range(1,len(ap_list)):
	print (formatString.format(nindex, ap_list[nindex],power_list[nindex],ESSID_list[nindex]))
