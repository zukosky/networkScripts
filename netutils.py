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