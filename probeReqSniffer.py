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
formatString ="{: <4} {: <10} {: <20} {: <20} {: <40}"
#formatString ="{: <4} {: <10} {: <20} {: <40}"
#Read the OUI Reference FIle
fName = "oui-clean.txt"
fileHandle = open(fName, 'r')
oui =[]
manu = []
for line in fileHandle:
    fields = line.split('|')  # Only reads one line at a time
    oui.append(fields[0])
    manu.append(fields[1].rstrip())  #.rstrip() removes the trailing \n
fileHandle.close()
ouiRef = dict(zip(oui,manu))
#print(ouiRef.keys())
#print(ouiRef.values())
def uniquePacketHandler(pkt) :
    if pkt.haslayer(Dot11) :
        if pkt.type == 0 and pkt.subtype == 4 :
		    #pkt.summary()
		    #Print if the combined MAC+AP
            if len(pkt.info) >0 and pkt.addr2 not in mac_list :
                mac_list.append(pkt.addr2)
                thisMac = pkt.addr2[:8].replace(':','-')
                thisMac = thisMac.upper()
                thisOui=ouiRef.get(thisMac,"")
                #print formatString.format(str(len(mac_list)), str(datetime.datetime.now().time())[0:8],pkt.addr2, pkt.info)
                print formatString.format(str(len(mac_list)), str(datetime.datetime.now().time())[0:8],
                                          pkt.addr2, pkt.info, thisOui)


#Scapy by default stores all packets.  Need store=0.
print formatString.format ("num","Time","MAC","ESSID","Manufacturer")
sniff(iface="wlan0", prn = uniquePacketHandler, store=0)