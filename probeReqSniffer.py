from scapy.all import *
import time
import datetime
import sys
from netutils import *
import signal
#from netutils import getMACAddressType
#from netutils import readOUIReference
#from netutils import readKnownMACs
from dot11PacketHandlers import *
import globalVar
def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
################################################################
# beaconSniffer.py
#
# This script will take a WLAN network card in Monitor mode and
# list all of the unique MAC address - Probe combinations
#
#################################################################

mac_count = []
TAB_1 = "\t"
DOT11_MANAGEMENT_FRAME = 0
DOT11_PROBE_REQUEST = 4

formatString ="{: <4} {: <8} {: <4} {: <18} {: <8} {: <20} {: <40} {: <15}"
#Read the OUI Reference FIle
global ouiRef
globalVar.ouiRef = readOUIReference()
fOutName = "probeOut.txt"
fileOutHandle = open(fOutName, 'w')
#Read the list of known (mostly local) MACs
globalVar.knownMACs = readKnownMACs()
#Scapy by default stores all packets.  Need store=0.
print (formatString.format ("num","Time","Pwr","MAC","MACType","ESSID","Manufacturer","KnownDevice"))

while (True):
#    sniff(iface="wlan0", prn=allProbesPacketHandler, filter="type mgt subtype probe-req", store=0)
#    sniff(iface="wlan0", prn = allKnownMACPacketHandler, store=0)
    try:
        sniff(iface="wlan0", prn = allFactoryPacketHandler, store=0)
#sniff(iface="wlan0", prn = allKnownMACPacketHandler, store=0)
#    sniff(iface="wlan0", prn=uniqueKnownPacketHandler, store=0)
# sniff(iface="wlan0", prn=uniqueNonRandomMACPacketHandler, filter="type mgt subtype probe-req", store=0)
#    sniff(iface="wlan0", prn=NonRandomCloseMACPacketHandler, filter="type mgt subtype probe-req", store=0)
    except (KeyboardInterrupt, SystemExit):
        raise
    except:
        e = sys.exc_info()[0]

