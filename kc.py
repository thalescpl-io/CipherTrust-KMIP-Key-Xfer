#####################################################################################
#
# 	Name: kc.py
# 	Author: Rick R
# 	Purpose: Python-based KMIP client to reading key attributes.  This variant
#            focuses on GKLM to CM KMIP key migration.  GKLM only requires
#            a client certificate for authentication, so the U/P has been removed
#            for source authentication.
#
#   Usage: py kc.py -srcHost <hostname or IP> 
#                   -dstHost <hostname or IP> -dstUser <username> -dstPass <password> 
#                   -clientCert CLIENTCERT -clientKey CLIENTKEY -trustedCAs TRUSTEDCAS
#
#####################################################################################

import os.path, pkgutil
import ssl
from kmip.pie.client import ProxyKmipClient, enums
from kmip.pie import objects
from kmip.pie import client
from kmip import enums
from kmip.core.factories import attributes
import binascii
import codecs
import hashlib
import argparse
import struct
import inspect

# ---------------- Functions-----------------------------------------------------
# -------------------------------------------------------------------------------
def makeHexStr(t_val):

    tmpStr = str(t_val)
    t_hexStr = hex(int("0x" + tmpStr[2:-1], 0))

    return t_hexStr

def makeByteStr(t_val):

    tmpStr = str(t_val)
    t_byteStr = bytes.fromhex(tmpStr[2:-1])

    return t_byteStr

def printKeyMaterial(t_keyIdx, t_keyID, t_hexKey):
    tmpstr = "\nkeyIdx: %s\n  keyID: %s\n  keyValue[keyIdx]: %s" %(t_keyIdx, t_keyID, t_hexKey)
    print(tmpstr)

def printKeyAttributes(t_keyAttrib):
    keyAttribIdx = 0
    for a in t_keyAttrib:

        # Get a more readable format of the digest
        if str(a.attribute_name) == "Digest":
            a_value = a.attribute_value.digest_value.value.hex()
        else:
            a_value = a.attribute_value

        # print attribute information
        tmpstr = "   keyAttribIdx: %s %s: %s" %(keyAttribIdx, a.attribute_name, a_value)    
        print(tmpstr)

        keyAttribIdx = keyAttribIdx + 1

# ---------------- End of Functions ----------------------------------------------

DEFAULT_KMIP_PORT = ["5696"]  # must be a list

LIST_OF_KEY_ATTRIBUTES = [
    enums.AttributeType.UNIQUE_IDENTIFIER.value,
    enums.AttributeType.NAME.value, 
    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM.value, 
    enums.AttributeType.CRYPTOGRAPHIC_LENGTH.value,
    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK.value,
    enums.AttributeType.OBJECT_TYPE.value,
    enums.AttributeType.STATE.value,
    enums.AttributeType.DIGEST.value
]

# ----- Input Parsing ------------------------------------------------------------

# Parse command.  Note that if the arguments are not complete, a usage message will be printed
# automatically
parser = argparse.ArgumentParser(prog="kc.py", description="KMIP Transfer Utility")

# Source Information
parser.add_argument("-srcHost", nargs=1, action="store", dest="srcHost", required=True)
parser.add_argument(
    "-srcPort", nargs=1, action="store", dest="srcPort", default=DEFAULT_KMIP_PORT
)
# parser.add_argument("-srcUser", nargs=1, action="store", dest="srcUser", required=True)
# parser.add_argument("-srcPass", nargs=1, action="store", dest="srcPass", required=True)

# Destination Information
parser.add_argument("-dstHost", nargs=1, action="store", dest="dstHost", required=True)
parser.add_argument(
    "-dstPort", nargs=1, action="store", dest="dstPort", default=DEFAULT_KMIP_PORT
)
parser.add_argument("-dstUser", nargs=1, action="store", dest="dstUser", required=True)
parser.add_argument("-dstPass", nargs=1, action="store", dest="dstPass", required=True)

# Client Certificate Information
parser.add_argument(
    "-clientCert", nargs=1, action="store", dest="clientCert", required=True
)
parser.add_argument(
    "-clientKey", nargs=1, action="store", dest="clientKey", required=True
)
parser.add_argument(
    "-trustedCAs", nargs=1, action="store", dest="trustedCAs", required=True
)

args = parser.parse_args()

t_srcHost = str(" ".join(args.srcHost))
t_srcPort = str(" ".join(args.srcPort))
# t_srcUser = str(" ".join(args.srcUser))
# t_srcPass = str(" ".join(args.srcPass))

t_dstHost = str(" ".join(args.dstHost))
t_dstPort = str(" ".join(args.dstPort))
t_dstUser = str(" ".join(args.dstUser))
t_dstPass = str(" ".join(args.dstPass))

t_clientCert = str(" ".join(args.clientCert))
t_clientKey = str(" ".join(args.clientKey))
t_trustedCAs = str(" ".join(args.trustedCAs))

print("\n ---- INPUT STATS: ----")
print("Source: ", t_srcHost, t_srcPort )
print("  Dest: ", t_dstHost, t_dstPort, t_dstUser)
print("Client: ", t_clientCert, t_clientKey, t_trustedCAs)

# ---- Parsing Complete ----------------------------------------------------------

# Specify key source KMIP Server and attributes
keySource = client.ProxyKmipClient(
    hostname=t_srcHost,
    port=t_srcPort,
    # username=t_srcUser,
    # password=t_srcPass,
    cert=t_clientCert,
    key=t_clientKey,
    ca=t_trustedCAs,
    # cert_reqs=ssl.CERT_OPTIONAL, # no longer supported although you may see this in the default pykmip.conf file, if used.
    ssl_version="PROTOCOL_TLSv1_2",
    config="client",
    config_file="pykmip.conf",
)


# Specify key destination KMIP Server and attributes - in this case it would be the same
keyDest = client.ProxyKmipClient(
    hostname=t_dstHost,
    port=t_dstPort,
    username=t_dstUser,
    password=t_dstPass,
    cert=t_clientCert,
    key=t_clientKey,
    ca=t_trustedCAs,
    # cert_reqs=ssl.CERT_OPTIONAL, # no longer supported although you may see this in the default pykmip.conf file, if used.
    ssl_version="PROTOCOL_TLSv1_2",
    config="client",
    config_file="pykmip.conf",
    kmip_version=enums.KMIPVersion.KMIP_1_4
)
# Alternative method for specifying KMIP Server.  Uses pykmip.conf file from default location.
# c = client.ProxyKmipClient()

# You need an attributes class defined for later use - location of existing keys
f = attributes.AttributeFactory()
keyAttribs = f.create_attribute(enums.AttributeType.OBJECT_TYPE, enums.ObjectType.SYMMETRIC_KEY)
#keyAttribs = f.create_attribute(enums.AttributeType.OBJECT_TYPE, enums.ObjectType.SYMMETRIC_KEY, enums.AttributeType.UNIQUE_IDENTIFIER)

name_index = 0  # To be confirmed below
keyIdx = 0
keyAttribIdx = 0
keyCount = 0
keyValueSrc = []    # list of source key values
keyAttribSrc = []   # list of source key attributes
listOfSrcKeys = []  # list of source key identifiers
keyValueDst = []    # list of destination key values
keyAttribDst = []   # list of destination key attributes
listOfDstKeys = []  # list of destination key identiers


# Code for locating (READING) keys and associated attributes for user from KMIP server. It limits its search to those
# attributes defined by the create_attributes object.
# This call initiates connection with KMIP server

print("\n ---- Copy Keys from Source Key Server ---- ")
try:
    with keySource:
        keyIdx = 0  # reset key index

        try:
            # listOfSrcKeys = keySource.locate(attributes=[keyAttribs])
            listOfSrcKeys = keySource.locate()

        except IOError as e:
            print("\n *** Source IO Error *** \n")
            print(e)
            exit()

        except ValueError as e:
            print("\n *** Source Value Error *** \n")
            print(e)
            exit()

        except EOFError as e:
            print("\n *** Source EOF Error *** ->  Is host available? Is user a member of Key Users?\n")
            print(e)
            exit()

        except Exception as e:
            print("\n *** Unknown Error with Source *** \n")
            print(e)
            # exit()        

        # The first 'tuple object is just a LIST of key IDs.  However, the second object is a nested tuple of THREE key-value pairs
        # consisting of attribute_name, attribute_index, attribute_value, and attribute_value.
        
        # Note that there is an issue with PyKMIP.  If the attribute call below throws an error like 
        # 'Unrecognized attribute type: AttributeType.ORIGINAL_CREATION_DATE' then refer to this note:
        # https://github.com/OpenKMIP/PyKMIP/issues/628
        

        keyCount = len(listOfSrcKeys)
        print("\nNumber of Src Keys: ", keyCount)

        for keySrcID in listOfSrcKeys:
            try:
                # Get key Material
                keyValueSrc.insert(keyIdx, keySource.get(keySrcID))
                keyValueDst.insert(keyIdx, keyValueSrc[keyIdx])  # make a copy
    
                # Get key attributes
                keyAttribSrc.insert(keyIdx, keySource.get_attributes(keySrcID))
                keyAttribDst.insert(keyIdx, keyAttribSrc[keyIdx])  # make a copy

                # Print key information
                hexKey = makeHexStr(keyValueSrc[keyIdx])
                printKeyMaterial(keyIdx, keySrcID, hexKey)

                # print attribute information
                printKeyAttributes(keyAttribSrc[keyIdx][1])                
                    
                keyIdx = keyIdx + 1

            except Exception as e:
                print("\n KeySrcID: ", keySrcID, "\n  KEY READ ERROR - Value and Atribute")
                print("  ", e)

except Exception as e:
    print("\n *** SOURCE SERVER NOT READY ***")
    print(e)
    exit()

# Now make copies of the keys on the destination key server

print("\n ---- Copy Keys to Destination Key Server ---- ")

try:
    with keyDest:
        keyCount = keyIdx
        keyIdx = 0  # reset key index
        print("\nNumber of Dst Keys: ", keyCount)

        while keyIdx < keyCount:
            keyAttribIdx = 0

            print("\nkeyIdx: ", keyIdx, "\n keyID: ", keyAttribDst[keyIdx][0])

            for d in keyAttribDst[keyIdx][1]:
                if str(d.attribute_name) == "Name":
                    C_Name = str(d.attribute_value)
                    print(" C_Name:", C_Name)
                    
                elif str(d.attribute_name) == "Cryptographic Usage Mask":

                    # Magic method for deconstructing usage mask...
                    L_UsageMask = []

                    # Determine the length of the numeration for all possible usage masks and
                    # then create a value with a ONE in the MSB (everything else are ZEROs).
                    # This value is called m_bit.
                    #
                    # Once it is created, apply it to the mask attribute value using AND)
                    # and determine if a bit is present in each of the positions of the mask, right-shift bit,
                    # and repeat.  If a bit is present in any location in the mask attribute valuye,
                    # then add that usage mask to the variable L_UsageMask.  
                    # Once you have iterated across all bit positions in the mask,
                    # then convert the list of cryptographic usage methods (L_UsageMask)
                    # to a tuple for association with the key.  
                    # 
                    # Whew!

                    bitLen = len(enums.CryptographicUsageMask)
                    m_bit = 2 ** (bitLen)
                    for bb in range(bitLen):
                        bit_test = m_bit & d.attribute_value.value
                        if bit_test > 0:
                            L_UsageMask.append(enums.CryptographicUsageMask(bit_test))
                        m_bit = m_bit >> 1
                    C_UsageMask = tuple(L_UsageMask)

                elif str(d.attribute_name) == "Cryptographic Length":
                    pass
                elif str(d.attribute_name) == "Cryptographic Algorithm":
                    pass
                elif str(d.attribute_name) == "State":
                    pass
                elif str(d.attribute_name) == "Operation Policy Name":
                    pass
                elif str(d.attribute_name) == "Object Type":
                    pass
                elif str(d.attribute_name) == "Unique Identifier":
                    C_UniqueID = str(d.attribute_value)
                    pass
                else:
                    d.attribute_value = None

                keyAttribIdx = keyAttribIdx + 1

            # now push the keys to the destination KMIP key list
            byteKey = makeByteStr(keyValueDst[keyIdx])
            
            # Create Key with minimal information
            symmetric_key = objects.SymmetricKey(
                enums.CryptographicAlgorithm.AES, 
                256, 
                byteKey
            )
            
            # Add additional attributes to Symmetric Key
            symmetric_key.unique_identifier = C_UniqueID
            symmetric_key.cryptographic_usage_masks = C_UsageMask
            symmetric_key.names[0] = C_Name
            symmetric_key.extractable = True
            symmetric_key.never_extractable = False
            
            # Upload the key, register the key, and activcate the key.
            try:
                kid = keyDest.register(symmetric_key)
                print("---- registered: ", C_Name)
                keyDest.activate(kid)
                print("----  activated: ", kid)

            except IOError as e:
                print("\n *** Destination IO Error *** \n")
                print(e)
                exit()

            except ValueError as e:
                print("\n *** Destination Value Error *** \n")
                print(e)
                exit()

            except EOFError as e:
                print("\n *** Destination EOF Error *** ->  Is host available? \n")
                print(e)
                exit()

            except Exception as e:
                print("\n *** Unknown Error with Destination - possible key duplication *** \n")
                print(e)

            keyIdx = keyIdx + 1
except Exception as e:
    print("\n *** DESTINATION SERVER NOT READY ***")
    print(e)
    exit()

##############################
# Now, let's got read from the destination server what keys it has
##############################
print("\n ---- Key Check  ---- ")

try:
    with keyDest:
        keyIdx = 0  # reset key index

        try:
            # listOfDstKeys = keyDest.locate(attributes=[keyAttribs])
            listOfDstKeys = keyDest.locate()

        except IOError as e:
            print("\n *** Destination IO Error *** \n")
            print(e)
            exit()

        except ValueError as e:
            print("\n *** Destination Value Error *** \n")
            print(e)
            exit()

        except EOFError as e:
            print("\n *** Destination EOF Error *** ->  Is host available? \n")
            print(e)
            exit()

        except Exception as e:
            print("\n *** Unknown Error with Destination *** \n")
            print(e)
            # exit()    

        # The first 'tuple object is just a LIST of key IDs.
        # However, the second object is a nested tubple of THREE key-valuye pairs
        # consisting of attribute_name, attribute_index, attribute_value, and attribute_value.
        # You can print(a) below to see a complete list of this information (keys and values)

        keyCount = len(listOfDstKeys)
        print("\nNumber of Destination Keys: ", keyCount)

        for keyDstID in listOfDstKeys:
            try:
                
                # Get key material and attributes
                keyValueDst.insert(keyIdx, keyDest.get(keyDstID))
                keyAttribDst.insert(keyIdx, keyDest.get_attributes(keyDstID, LIST_OF_KEY_ATTRIBUTES))

                # Print key information
                hexKey = makeHexStr(keyValueDst[keyIdx])
                printKeyMaterial(keyIdx, keyDstID, hexKey)
                
                # print attribute information
                printKeyAttributes(keyAttribDst[keyIdx][1])  
                
                keyIdx = keyIdx + 1

            except Exception as e:
                print("\n  KEY READ ERROR - Value and Atribute --> ", e)
                print("   keyIdx: ", keyIdx, "   keyDstID: ", keyDstID)    
                exit()
                
except Exception as e:
    print("\n *** DESTINATION SERVER NOT READY ***")
    print(e)
    exit()
    
print("\n --- COMPLETE --- ")
