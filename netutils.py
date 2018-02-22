import globalVar
import time
import sys, os, signal, random
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
