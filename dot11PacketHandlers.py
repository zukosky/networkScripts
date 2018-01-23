from scapy.all import *
import time
import datetime
import sys
import globalVar
from netutils import *


DOT11_MANAGEMENT_FRAME = 0
DOT11_PROBE_REQUEST = 4
formatString = "{: <4} {: <8} {: <4} {: <18} {: <8} {: <20} {: <40} {: <15}"

######################################################################
#
# allProbesPacketHandler()
#
# This packet handler is for capturing every single probe request.
# No filtering is done.
#
######################################################################
def allProbesPacketHandler(pkt):
    global ouiRef
    if pkt.haslayer(Dot11):
        if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST:
            thisMac = pkt.addr2
            thisOui = thisMac[:8].replace(':', '-')
            thisOui = thisOui.upper()
            thisManu = globalVar.ouiRef.get(thisOui, "")
            thisKnownDevice = ""
            try:
                extra = pkt.notdecoded
                rssi = -(256 - ord(extra[-4:-3]))
            except:
                rssi = -100
            print formatString.format(1, str(datetime.datetime.now().time())[0:8], rssi,
                                      pkt.addr2, getMACAddressType(pkt.addr2),
                                      pkt.info, thisManu, thisKnownDevice)
######################################################################
#
# allProbesPacketHandler()
#
# This packet handler is for capturing only MAC addresses that are in
# a predefined list
#
######################################################################
def allKnownMACPacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST:
            thisMac = pkt.addr2
            thisOui = thisMac[:8].replace(':', '-')
            thisOui = thisOui.upper()
            thisManu = globalVar.ouiRef.get(thisOui, "")
            thisKnownDevice = globalVar.knownMACs.get(thisMac, "")
            try:
                extra = pkt.notdecoded
                rssi = -(256 - ord(extra[-4:-3]))
            except:
                rssi = -100
            if (len(thisKnownDevice) > 0):
                print formatString.format(1, str(datetime.datetime.now().time())[0:8], rssi,
                                              pkt.addr2, getMACAddressType(pkt.addr2),
                                              pkt.info, thisManu, thisKnownDevice)