from scapy.all import *
import time
import datetime
import sys
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
DOT11_MANAGEMENT_FRAME = 0
DOT11_PROBE_REQUEST = 8
formatString ="{: <4} {: <10} {: <10} {: <20} {: <20} {: <40}"
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
    try:
        if pkt.haslayer(Dot11) :
            if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST :
                #print(pkt.summary())
                #print(pkt)
                #Print if the combined MAC+AP

                #if len(pkt.info)>0 and pkt.addr2 not in mac_list :
                if pkt.addr2 not in mac_list:
                    mac_list.append(pkt.addr2)
                    thisMac = pkt.addr2[:8].replace(':','-')
                    thisMac = thisMac.upper()
                    thisOui=ouiRef.get(thisMac,"")
                    try:
                        extra = pkt.notdecoded
                        rssi = -(256 - ord(extra[-4:-3]))
                    except:
                        rssi = -100
                    #ls(pkt)
                    #print formatString.format(str(len(mac_list)), str(datetime.datetime.now().time())[0:8],pkt.addr2, pkt.info)
                    print formatString.format(str(len(mac_list)), str(datetime.datetime.now().time())[0:8],
                                              rssi, pkt.addr2, pkt.info, thisOui)
    except KeyboardInterrupt:
        print("goodbye")
        raise
        sys.exit()

#Scapy by default stores all packets.  Need store=0.
print formatString.format ("num","Time","Power","MAC","ESSID","Manufacturer")
try:
    while (True):
        sniff(iface="wlan0", prn = uniquePacketHandler, store=0)
except KeyboardInterrupt:
    print("goodbye")
    raise
    sys.exit()
#except:
#    e = sys.exc_info()[0]
#    except socket.error:
#    print("socket error. continuing")
#    except:

#       print("Error: %s" % e)
#       print("Continuing...")

