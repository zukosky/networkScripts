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
DOT11_PROBE_REQUEST = 4
formatString ="{: <10} {: <10} {: <20} {: <20} {: <40}"
#formatString ="{: <4} {: <10} {: <20} {: <40}"
#Read the OUI Reference FIle
fName = "oui-clean.txt"
fileHandle = open(fName, 'r')
workMAC = "b8:d7:af:6c:15:fb"
homeMAC = "2c:0e:3d:53:dd:83"
ipadMAC = "ac:cf:5c:7e:98:3f"
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
                if pkt.addr2.lower() == "9c:3d:cf:0f:b9:15":
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
                    print formatString.format(str(datetime.datetime.now().time())[0:8],
                                              rssi, pkt.addr2, pkt.info, thisOui)
    except KeyboardInterrupt:
        print("goodbye inside function")
        sys.exit()

#Scapy by default stores all packets.  Need store=0.
print formatString.format ("Time","Power","MAC","ESSID","Manufacturer")
#while (True):
#    sniff(iface="wlan0", prn = uniquePacketHandler, store=0)

while (True):
    try:
        sniff(iface="wlan0", prn = uniquePacketHandler, store=0)
    except KeyboardInterrupt:
        print("goodbye outside function")
        sys.exit()
#    except:
#        e = sys.exc_info()[0]
#    except socket.error:
#        print("socket error. continuing")
#    except:

#       print("Error: %s" % e)
#       print("Continuing...")

