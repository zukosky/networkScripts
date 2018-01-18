from scapy.all import *
import time
import datetime
import sys
from netutils import getMACAddressType
################################################################
# beaconSniffer.py
#
# This script will take a WLAN network card in Monitor mode and
# list all of the unique MAC address - Probe combinations
#
#################################################################
#################################################################
# Function for reading the list of local MAC address (my own devices)
#################################################################
def getLocalMACs():
    oui=[]
    manu=[]
    desc=[]
    lmfname= "localMAC.txt"
    fileHandle = open(lmfname, 'r')
    for line in fileHandle:
        fields = line.split('|')  # Only reads one line at a time
        oui.append(fields[0])
        manu.append(fields[1])
        desc.append(fields[2].rstrip())
    fileHandle.close()
    #localMACs = {oui[i]:manu[i]:desc[i] for i in xrange(len(oui))}
    #localMACs = dict(zip(oui,zip(manu,desc)))
    localMACs = dict((z[0],list(z[1:])) for z in zip(oui,manu,desc))
#    localMACs = {z[0]:list(z[1:])) for z in zip(oui,manu,desc)}
    return localMACs

mac_list = []
mac_count = []
TAB_1 = "\t"
DOT11_MANAGEMENT_FRAME = 0
DOT11_PROBE_REQUEST = 4
formatString ="{: <4} {: <10} {: <5} {: <20} {: <10} {: <20} {: <40}"
#Read the OUI Reference FIle
fName = "oui-clean.txt"
fileHandle = open(fName, 'r')
fOutName = "probeOut.txt"
fileOutHandle = open(fOutName, 'w')
oui =[]
manu = []
for line in fileHandle:
    fields = line.split('|')  # Only reads one line at a time
    oui.append(fields[0])
    manu.append(fields[1].rstrip())  #.rstrip() removes the trailing \n
fileHandle.close()
ouiRef = dict(zip(oui,manu))

localMACs = getLocalMACs()
print(localMACs)
#print(ouiRef.keys())
#print(ouiRef.values())
def uniquePacketHandler(pkt) :
    try:
        if pkt.haslayer(Dot11) :
            if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST :
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
                                              rssi, pkt.addr2,getMACAddressType(pkt.addr2), pkt.info, thisOui)
                    fileOutHandle.write(formatString.format(str(len(mac_list)), str(datetime.datetime.now().time())[0:8],
                                              rssi, pkt.addr2, pkt.info, thisOui))
    except KeyboardInterrupt:
        print("goodbye inside function")
        sys.exit()

#Scapy by default stores all packets.  Need store=0.
print formatString.format ("num","Time","Power","MAC","MACType","ESSID","Manufacturer")
while (True):
    try:
        sniff(iface="wlan0", prn = uniquePacketHandler, store=0)
    except KeyboardInterrupt:
        print("goodbye outside function")
        sys.exit()
    except:
        e = sys.exc_info()[0]

