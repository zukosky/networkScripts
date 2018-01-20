from scapy.all import *
import time
import datetime
import sys
from netutils import getMACAddressType
from netutils import readOUIReference
from netutils import readKnownMACs
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
probeCount = 0
formatString ="{: <4} {: <8} {: <4} {: <18} {: <8} {: <20} {: <40} {: <15}"

#Read the OUI Reference FIle
ouiRef = readOUIReference()
fOutName = "probeOut.txt"
fileOutHandle = open(fOutName, 'w')

#Read the list of known (mostly local) MACs
knownMACs = readKnownMACs()

def uniquePacketHandler(pkt) :
    try:
        if pkt.haslayer(Dot11) :
            if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST :
                #if len(pkt.info)>0 and pkt.addr2 not in mac_list :
                if pkt.addr2 not in mac_list:
                    mac_list.append(pkt.addr2)
                    thisMac = pkt.addr2
                    thisOui = thisMac[:8].replace(':','-')
                    thisOui = thisOui.upper()
                    thisManu=ouiRef.get(thisOui,"")
                    thisKnownDevice = knownMACs.get(thisMac, "")
                    try:
                        extra = pkt.notdecoded
                        rssi = -(256 - ord(extra[-4:-3]))
                    except:
                        rssi = -100
                    probeCount = probeCount + 1
                    print formatString.format(probeCount, str(datetime.datetime.now().time())[0:8],rssi, pkt.addr2,getMACAddressType(pkt.addr2),
                                              pkt.info, thisManu,thisKnownDevice)
                    fileOutHandle.write(formatString.format(str(len(mac_list)), str(datetime.datetime.now().time())[0:8],
                            rssi, pkt.addr2, pkt.info, thisOui))
    except KeyboardInterrupt:
        print("goodbye inside function")
        sys.exit()

def allKnownMACPacketHandler(pkt):
    try:
        if pkt.haslayer(Dot11):
            if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST:
                thisMac = pkt.addr2
                thisOui = thisMac[:8].replace(':', '-')
                thisOui = thisOui.upper()
                thisManu = ouiRef.get(thisOui, "")
                thisKnownDevice = knownMACs.get(thisMac, "")
                try:
                    extra = pkt.notdecoded
                    rssi = -(256 - ord(extra[-4:-3]))
                except:
                    rssi = -100
                if(len(thisKnownDevice)>0):
                    print formatString.format(str(len(mac_list)), str(datetime.datetime.now().time())[0:8], rssi,
                                          pkt.addr2, getMACAddressType(pkt.addr2),
                                          pkt.info, thisManu, thisKnownDevice)
    except KeyboardInterrupt:
        print("goodbye inside function")
        sys.exit()

#Scapy by default stores all packets.  Need store=0.
print formatString.format ("num","Time","Pwr","MAC","MACType","ESSID","Manufacturer","KnownDevice")

while (True):
    try:
#        sniff(iface="wlan0", prn = uniquePacketHandler, store=0)
        sniff(iface="wlan0", prn = allKnownMACPacketHandler, store=0)
    except KeyboardInterrupt:
        print("goodbye outside function")
        sys.exit()
    except:
        e = sys.exc_info()[0]

