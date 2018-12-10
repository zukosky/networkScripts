import globalVar
import time
import sys, os, signal, random
import datetime
#################################################################
# Function for deciding if a MAC address is random/administratively assigned
#################################################################
def getMACAddressType(MACAddress):
    # Administratively assigned addresses have bit 1 = 1
    binVal = int(MACAddress[:2], 16)
    if((binVal & 2)>0):
        MACType = "Random"
    else:
        MACType = "Factory"
    return(MACType)
#################################################################
# Function for reading if an OUI reference file
#################################################################
def readOUIReference():
    global ouiRef
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
    return ouiRef  #This might be superflous
#################################################################
# Function for reading the list of known MAC address (my own devices)
#################################################################
def readKnownMACs():
    oui=[]
    manu=[]
    desc=[]
    lmfname= "knownMACs.txt"
    fileHandle = open(lmfname, 'r')
    for line in fileHandle:
        fields = line.split('|')  # Only reads one line at a time
        oui.append(fields[0])
        manu.append(fields[1])
        desc.append(fields[2].rstrip())
    fileHandle.close()
    #knownMACs = dict((z[0],list(z[1:])) for z in zip(oui,desc))
    knownMACs = dict(zip(oui,desc))
    return knownMACs
#################################################################
# Function for reading the list of addresses who's logging should 
# be suppressed (hidden)
#################################################################
def readHiddenMACs():
    oui=[]
    desc=[]
    lmfname= "hiddenMACs.txt"
    fileHandle = open(lmfname, 'r')
    for line in fileHandle:
        if line[0:0] != "#" and len(line) > 1 :
            fields = line.split('#')  # Only reads one line at a time
            oui.append(fields[0])
            desc.append(fields[1])            
    fileHandle.close()
    hiddenMACs = oui  #Temporarily just storing the oui
    return hiddenMACs
#################################################################
# Function for creating a dictionary of important characteristics of a MAC address
#################################################################
def detailMac(macaddr):

    macDetails={}
    macDetails['mac_address'] = macaddr
    #Oui reference fill is upper case and uses dashes
    macDetails['oui'] = macaddr[:8].replace(':', '-').upper()
    #Get the manufacturer from the global dictionary
    macDetails['manufacturer'] = globalVar.ouiRef.get(macDetails['oui'], "")
    #Store a short version of the manufactuer.  The first word is usually significant
    macDetails['short_manufacturer'] = macDetails['manufacturer'].split()[0]
    #Is this a known device?
    macDetails['known_device'] = globalVar.knownMACs.get(macaddr, "")
    macDetails['mac_address_type'] = getMACAddressType(macaddr)
    return macDetails
#################################################################
# Function for creating a dictionary of important characteristics
# from an 802.11 probe packet
#################################################################
def parse80211Packet(pkt):

    pktInfo={}
    pktInfo['mac_address'] = pkt.addr2
    thisOui = pkt.addr2[:8].replace(':','-')
    thisOui = thisOui.upper()
    pktInfo['oui'] = thisOui
    pktInfo['manufacturer'] = globalVar.ouiRef.get(thisOui,"")
    pktInfo['known_device'] = globalVar.knownMACs.get(pkt.addr2, "")
    pktInfo['mac_address_type'] = getMACAddressType(pkt.addr2)
    pktInfo['datetime'] = str(datetime.datetime.now().time())    
    pktInfo['datetime_short'] = str(datetime.datetime.now().time())[0:8]        
    pktInfo['ESSID'] = pkt.info.decode("utf-8")
    try:
        extra = pkt.notdecoded
        rssi = -(256 - ord(extra[-4:-3]))
    except:
        rssi = -100
    pktInfo['rssi'] = rssi
    return pktInfo
def set_wifi_channel(chan):
    #################################################################
    # Function for changing the channel the WIFI card is listening on
    #################################################################    
    os.system("iw dev wlan0 set channel %d" % (chan))
#################################################################
# Function for randomly changing the channel the WIFI card is listening on
#################################################################
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,12)
            set_wifi_channel(channel)
            #os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break
