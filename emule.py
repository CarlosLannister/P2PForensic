#Emule module 

import os   # To get filesizes and path
import time  # To get the actual time
import binascii  # To convert hex-strings to ascii
import sys # exits
import csv # To write csv-files
import re # Regex to search for magic bytes in unallocated clusters


headerfilesize = b"03010002"
headertotalupload = b"03010050"
headerrequests = b"03010051"
headeracceptedrequests = b"03010052"
headeruploadpriority = b"03010019"
headerpartname = b"02010012"


def getblockofdata(i,fobj, filesize): 
# Seraching a block of data. A block starts with the filenameheader 0x02010001 and ends directly in front of the next
# filenameheader or it will be delimited at a length of maxblocksizes bytes or at the end of file.  
    
    blockcounter = 0
    fobj.seek((i+6+blockcounter),0)
    headersucher = (fobj.read(4))

    #Magic Bytes
    maxblocksize = 1024 # Delimit block after x bytes, if there cant be found another filename header. 

    while headersucher != b"\x02\x01\x00\x01":
        blockcounter += 1
        
        if i + blockcounter >= filesize:      # Stop at EOF
            break
        elif blockcounter >= maxblocksize:    # Stop when maximal blocksize has been reached
            break
        fobj.seek((i+6+blockcounter),0)
        headersucher = (fobj.read(4))


    fobj.seek((i),0)
    block =  (fobj.read(blockcounter+6))
    block=binascii.hexlify(block)
    return block

def carvefilename(block):# Takes offset 8-10 and 10-12 changes byteorder and make an decimal of it
    filenamelength = (block[10:12])
    filenamelength = filenamelength + (block[8:10])
    filenamelength = int(filenamelength,16)
    filename = block[12:((filenamelength*2)+12)]
    filename = binascii.unhexlify(filename)

    try: # Try to use filename as an utf-8 string. 
        filename = filename.decode("utf-8")
    except:
        filename = str(filename)
        filename = filename.lstrip("b'")
        filename = filename.rstrip("'")
    
    return str(filename)

def carvefilesize(block):
    filesizeentry = "Not Found"
    try:
        indexinblock = block.index(headerfilesize)
        filesizeentry = block[indexinblock+8:indexinblock+16]      # Big endian
        entrylittleendian = filesizeentry[6:8] + filesizeentry[4:6] + filesizeentry[2:4] + filesizeentry[0:2] # Der Big Endian Eintrag wird auf Little Endian umgebogen
        filesizeentry = int(entrylittleendian,16)  # Litte endian in decimal
        return filesizeentry
    except:
        return filesizeentry
    
def carvetotalupload(block): 
    totalupload = 0
    try:
        indexinblock = block.index(headertotalupload)
        uploadentry = block[indexinblock+8:indexinblock+16]      # Big endian
        entrylittleendian = uploadentry[6:8] + uploadentry[4:6] + uploadentry[2:4] + uploadentry[0:2] # Der Big Endian Eintrag wird auf Little Endian umgebogen
        totalupload = int(entrylittleendian,16)  # Litte endian in dezimal
        return(totalupload)
    except:
        return(totalupload)
    
def carverequests(block):
    requests = 0
    try:
        indexinblock = block.index(headerrequests)
        requestsentry = block[indexinblock+8:indexinblock+16]      # Big endian
        entrylittleendian = requestsentry[6:8] + requestsentry[4:6] + requestsentry[2:4] + requestsentry[0:2] # Der Big Endian Eintrag wird auf Little Endian umgebogen
        requests = int(entrylittleendian,16)  # Litte endian in dezimal
        return(requests)
    except:
        return(requests)
    
def carveacceptedrequests(block):
    acceptedrequests = 0
    try:
        indexinblock = block.index(headeracceptedrequests)
        acceptedrequestssentry = block[indexinblock+8:indexinblock+16]      # Big endian
        entrylittleendian = acceptedrequestssentry[6:8] + acceptedrequestssentry[4:6] + acceptedrequestssentry[2:4] + acceptedrequestssentry[0:2] # Der Big Endian Eintrag wird auf Little Endian umgebogen
        acceptedrequests = int(entrylittleendian,16)  # Litte endian in dezimal
        return(acceptedrequests)
    except:
        return(acceptedrequests)
    
def carveuploadpriority(block):
    uploadpriority = "Not Found"
    try:
        indexinblock = block.index(headeruploadpriority)
        uploadpriorityentry = block[indexinblock+8:indexinblock+10] # Just one byte needet for upload priority
        if uploadpriorityentry == b"05":
            uploadpriority = "Auto"
        elif uploadpriorityentry == b"00":
            uploadpriority = "Low"
        elif uploadpriorityentry == b"01":
            uploadpriority = "Normal"
        elif uploadpriorityentry == b"02":
            uploadpriority = "High"
        elif uploadpriorityentry == b"03":
            uploadpriority = "Release"
        elif uploadpriorityentry == b"04":
            uploadpriority = "Very Low"
        return(uploadpriority)
    except:
        return(uploadpriority)
    
def carvepartfile(block): 
    partfile = "Not Found"
    try:
        indexinblock = block.index(headerpartname)
        laengepartfile = int(block[indexinblock+10:indexinblock+12] + block[indexinblock+8:indexinblock+10],16)   #read value, change byte order and convert to decimal
        partfile = binascii.unhexlify(partfile)
        partfile = str(partfile)
        partfile = partfile.lstrip("b'")
        partfile = partfile.rstrip("'")
        return(partfile)
    except:
        return(partfile)

