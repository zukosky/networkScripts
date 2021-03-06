from scapy.all import *
#import scapy
import time
import datetime
import sys
import globalVar
import signal
from netutils import *
mac_list = []
pkt_list = []

DOT11_MANAGEMENT_FRAME = 0
DOT11_PROBE_REQUEST = 4
formatString = "{:<4} {:<8} {:<4} {:<18} {:<8} {:<20} {:<40} {:<15}"


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
            thisKnownDevice = globalVar.knownMACs.get(thisMac, "")
            try:
                extra = pkt.notdecoded
                rssi = -(256 - ord(extra[-4:-3]))
            except:
                rssi = -100
            print (formatString.format(1, str(datetime.datetime.now().time())[0:8], rssi,
                                      pkt.addr2, getMACAddressType(pkt.addr2),
                                      pkt.info, thisManu, thisKnownDevice))
######################################################################
#
# allKnownMACPacketHandler()
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
                print (formatString.format(1, str(datetime.datetime.now().time())[0:8], rssi,
                                              pkt.addr2, getMACAddressType(pkt.addr2),
                                              pkt.info, thisManu, thisKnownDevice))
######################################################################
#
# uniquePacketHandler()
#
# This packet handler is for capturing unique MAC addresses.  If a MAC
# shows up once it won't be displayed again.
#
######################################################################

def uniquePacketHandler(pkt) :
    try:
        if pkt.haslayer(Dot11) :
            if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST :
                MACType = getMACAddressType(pkt.addr2)
                if pkt.addr2 not in mac_list and MACType == "Factory":
                    mac_list.append(pkt.addr2)
                    thisMac = pkt.addr2
                    thisOui = thisMac[:8].replace(':','-')
                    thisOui = thisOui.upper()
                    thisManu=globalVar.ouiRef.get(thisOui,"")
                    thisKnownDevice = globalVar.knownMACs.get(thisMac, "")
                    try:
                        extra = pkt.notdecoded
                        rssi = -(256 - ord(extra[-4:-3]))
                    except:
                        rssi = -100
                    print (formatString.format(len(mac_list), str(datetime.datetime.now().time())[0:8],rssi, pkt.addr2,getMACAddressType(pkt.addr2),
                                                pkt.info.decode("utf-8"), thisManu,thisKnownDevice))
    except (KeyboardInterrupt, SystemExit):
        raise
    except:
        e = sys.exc_info()[0]

######################################################################
#
# allFactoryPacketHandler()
#
# This packet handler is for capturing and logging to disk
# all probes with factory MACs.xxx
#
######################################################################

def allFactoryPacketHandler(pkt) :
    if pkt.haslayer(Dot11) :
        if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST :
#            print("Have a packet")
            MACType = getMACAddressType(pkt.addr2)
#            print("MAC Address is:" + MACType)
            if MACType == "Factory":
                pktDict = parse80211Packet(pkt)
                print("Parsed a packet")
                print(globalVar.hiddenMACs.values() )
                if pktDict['mac_address'] not in globalVar.hiddenMACs.values() :
#                if True :
                    print("Not in our oui list")
                    pkt_list.append(pktDict)
                    #thisMac = pkt.addr2
                    #thisOui = thisMac[:8].replace(':','-')
                    #thisOui = thisOui.upper()
                    #thisManu=globalVar.ouiRef.get(thisOui,"")
                    #thisKnownDevice = globalVar.knownMACs.get(thisMac, "")
                    #try:
                    #    extra = pkt.notdecoded
                    #    rssi = -(256 - ord(extra[-4:-3]))
                    #except:
                    #    rssi = -100
                    print (formatString.format(len(pkt_list), pktDict['datetime_short'], 
                        pktDict['rssi'],
                        pktDict['mac_address'],
                        pktDict['mac_address_type'],
                        pktDict['ESSID'],
                        pktDict['manufacturer'],
                        pktDict['known_device']))
#                print (formatString.format(len(pkt_list), str(datetime.datetime.now().time())[0:8],rssi, pkt.addr2,getMACAddressType(pkt.addr2),
#                                                pkt.info.decode("utf-8"), thisManu,thisKnownDevice))
######################################################################
#
# uniqueNonRandomMACPacketHandler()
#
# This packet handler is for capturing the first instance of a unique factory MAC address
#
######################################################################
def uniqueNonRandomMACPacketHandler(pkt) :
    if pkt.haslayer(Dot11) :
        if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST :
            if pkt.addr2 not in mac_list and getMACAddressType(pkt.addr2) == "Factory":
                mac_list.append(pkt.addr2)
                #Get details about the MAC address
                macDict = detailMac(pkt.addr2)
                try:
                    extra = pkt.notdecoded
                    rssi = -(256 - ord(extra[-4:-3]))
                except:
                    rssi = -100
#               xxx
#               formatString = "{:<4} {:<8} {:<4} {:<18} {:<8} {:<20} {:<40} {:<15}"
#                formatString = "{:<4} {:<8}  {:<4}  {:<18}  {:<8} {:<20}  {:<40} {:<15}"
                print (formatString.format(len(mac_list), str(datetime.datetime.now().time())[0:8],
                        rssi,macDict['mac_address'],macDict['mac_address_type'],
                        pkt.info.decode("utf-8"),macDict['manufacturer'],macDict['known_device']))
#                print (formatString.format(str(len(mac_list)), str(datetime.datetime.now().time())[0:8],str(rssi), macDict['mac_address'],
#                                          macDict['mac_address_type'],
#                                              pkt.info, macDict['manufacturer'],macDict['known_device']))
######################################################################
#
# NonRandomCloseMACPacketHandler()
#
# This packet handler is for capturing the first instance of a unique factory MAC address,
# but only if the power is greater than a limit
#
######################################################################
def NonRandomCloseMACPacketHandler(pkt) :
    powerLimit = -70
    if pkt.haslayer(Dot11) :
        if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST :
            if getMACAddressType(pkt.addr2) == "Factory":
                #Get details about the MAC address
                macDict = detailMac(pkt.addr2)
                try:
                    extra = pkt.notdecoded
                    rssi = -(256 - ord(extra[-4:-3]))
                except:
                    rssi = -100
                if rssi > powerLimit and macDict['known_device']!="PAZInspiron2013" \
                                    and macDict['known_device'] != "NBR1" \
                        and macDict['known_device'] != "KPK" \
                        and macDict['known_device'] != "Sony TV" \
                        and macDict['known_device'] != "Amazon Echo" \
                        and macDict['known_device'] != "NBR2":

                        print (formatString.format("", str(datetime.datetime.now().time())[0:8],rssi, macDict['mac_address'],
                                          macDict['mac_address_type'],
                                              pkt.info, macDict['manufacturer'],macDict['known_device']))
######################################################################
#
# uniqueKnownPacketHandler()
#
# This packet handler is for capturing unique MAC addresses from a known list.
# It will capture the first instance of a MAC being seen
#
######################################################################

def uniqueKnownPacketHandler(pkt) :
    try:
        if pkt.haslayer(Dot11) :
            if pkt.type == DOT11_MANAGEMENT_FRAME and pkt.subtype == DOT11_PROBE_REQUEST :
                thisMac = pkt.addr2
                thisKnownDevice = globalVar.knownMACs.get(thisMac, "")
#                print("Size of mac_list in uniqueKnownPacketHandler:")
#                print(len(mac_list))
                macDict = detailMac(pkt.addr2)
                if pkt.addr2 not in mac_list and (len(thisKnownDevice) > 0):

                    mac_list.append(pkt.addr2)
                    try:
                        extra = pkt.notdecoded
                        rssi = -(256 - ord(extra[-4:-3]))
                    except:
                        rssi = -100
                    formatString = "{:<4} {:<8}"
                    print (formatString.format("123", str(datetime.datetime.now().time())[0:8]))
#                    formatString = "{:<4} {:<8} {:<4} {:<18} {:<8} {:<20} {:<40} {:<15}"
#                    print (formatString.format("", str(datetime.datetime.now().time())[0:8],str(rssi), macDict['mac_address'],
#                                          macDict['mac_address_type'],
#                                              pkt.info, macDict['manufacturer'],macDict['known_device']))

#                    print (formatString.format(len(mac_list), str(datetime.datetime.now().time())[0:8],rssi, pkt.addr2,getMACAddressType(pkt.addr2),
#                                              pkt.info, thisManu,thisKnownDevice))
#                    fileOutHandle.write(formatString.format(str(len(mac_list)), str(datetime.datetime.now().time())[0:8],
#                            rssi, pkt.addr2, pkt.info, thisOui))
    except KeyboardInterrupt:
        print("goodbye inside function")
        sys.exit()
