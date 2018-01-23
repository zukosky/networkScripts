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
    print("reading ouiref")
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