########################################################################
#
#	Name: kc.py
#	Author: Rick R
#	Purpose:  Python-based KMIP client to reading key attributes
#
########################################################################

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

# ---------------- Functions -------------------------------------------------------------------

# ----------------------------------------------------------------------------------------------
def makeHexStr(t_val):
#-----------------------------------------------------------------------------------------------
	
	tmpStr = str(t_val)
	t_hexStr = hex(int("0x"+tmpStr[2:-1], 0))

	return t_hexStr


# ---------------- End of Functions -------------------------------------------------------------

# Specify key source KMIP Server and attributes
keySource =	client.ProxyKmipClient(
			hostname='192.168.1.184',
			port='5696',
			cert='kmipclient.crt',
			key='kmipclient.key',
			ca='TrustedCAs.pem',
#			cert_reqs=ssl.CERT_OPTIONAL, # no longer supported although you may see this in the default pykmip.conf file, if used.
			ssl_version="PROTOCOL_TLSv1_2",
			username='kmip_alice',
			password='Thales123!',
#			username='admin',
#			password='em50-UAV2000',	
    		config='client',
    		config_file='pykmip.conf'	
)


# Specify key destination KMIP Server and attributes - in this case it would be the same
keyDest =	client.ProxyKmipClient(
			hostname='192.168.1.184',
			port='5696',
			cert='kmipclient.crt',
			key='kmipclient.key',
			ca='TrustedCAs.pem',
#			cert_reqs=ssl.CERT_OPTIONAL, # no longer supported although you may see this in the default pykmip.conf file, if used.
			ssl_version="PROTOCOL_TLSv1_2",
			username='kmip_bob',
			password='Thales234!',
    		config='client',
    		config_file='pykmip.conf'	
)
# Alternative method for specifying KMIP Server.  Uses pykmip.conf file from default location.
#c = client.ProxyKmipClient()

# You need an attributes class defined for later use - location of existing keys
f = attributes.AttributeFactory()
keyAttribs = f.create_attribute(
	enums.AttributeType.OBJECT_TYPE,
	enums.ObjectType.SYMMETRIC_KEY
	)

name_index 		= 0		# To be confirmed below
keyIdx 			= 0
keyAttribIdx	= 0
keyCount		= 0
keyValueSrc 	= []	# list of keys
keyAttribSrc 	= []	# list of key attributes
listOfSrcKeys	= []
keyValueDst 	= []	# list of keys
keyAttribDst 	= []	# list of key attributes
listOfDstKeys	= []

# Code for locating (READING) keys and associated attributes for user from KMIP server. It limits its search to those
# attributes defined by the create_attributes object.
# This call initiates connection with KMIP server

print("\n ---- Copy Keys from Source Key Server ---- ")

with keySource:
	keyIdx = 0	#reset key index
#	listOfSrcKeys = keySource.locate(attributes=[keyAttribs])
	listOfSrcKeys = keySource.locate()

# The first 'tuple object is just a LIST of key IDs.  However, the second object is a nested tubple of THREE key-value pairs 
# consisting of attribute_name, attribute_index, attribute_value, and attribute_value.  

	keyCount = len(listOfSrcKeys)
	print("\nNumber of Src Keys: ", keyCount)
	
	for keySrcID in listOfSrcKeys:
		try:
			keyValueSrc.insert(keyIdx, keySource.get(keySrcID))
			keyValueDst.insert(keyIdx, keyValueSrc[keyIdx]) 	# make a copy

			keyAttribSrc.insert(keyIdx, keySource.get_attributes(keySrcID))
			keyAttribDst.insert(keyIdx, keyAttribSrc[keyIdx])	# make a copy

			hexKey = makeHexStr(keyValueSrc[keyIdx])
			
			print("\nkeyIdx: ", keyIdx, "\n  keySrcID: ", keySrcID, "\n  keyValueSrc[keyIdx]: ", hexKey)

			keyAttribIdx = 0
			for a in keyAttribSrc[keyIdx][1]:
				
				#Get a more readable format of the digest
				if(str(a.attribute_name) == 'Digest'):
					a_value = a.attribute_value.digest_value.value.hex()
				else:
					a_value = a.attribute_value
					
				print("keyIdx: ", keyIdx, "keyAttribIdx: ", keyAttribIdx, a.attribute_name, ": ", a_value)
				keyAttribIdx = keyAttribIdx + 1
				
			keyIdx = keyIdx + 1
			
		except:
			print("\n KeySrcID: ", keySrcID, "\n  KEY READ ERROR - Value and Atribute")


# Now make copies of the keys on the destination key server
print("\n ---- Copy Keys to Destination Key Server ---- ")

with keyDest:
	keyCount = keyIdx
	keyIdx = 0	#reset key index
	print("\nNumber of Dst Keys: ", keyCount)	

	while (keyIdx < keyCount):
		keyAttribIdx = 0
		
		print("\nkeyIdx: ", keyIdx,"\n keyID: ", keyAttribDst[keyIdx][0] )
		
		for d in keyAttribDst[keyIdx][1]:
			if(str(d.attribute_name) == 'Name'):
				d.attribute_value = str(d.attribute_value) + "_V2"
				C_Name = d.attribute_value
				print(" C_Name: :", C_Name)
			elif(str(d.attribute_name) == 'Cryptographic Usage Mask'):
		
			# Magic method for deconstructing usage mask...
				L_UsageMask = []
			
			# Determine the length of the numeration for all possible usage masks and
			# then create a value with a ONE in the MSB (everything else are ZEROs).
			# This value is called m_bit.  Once it is created, apply it to the mask attribute value using AND)
			# and determine if a bit is present in each of the positions of the mask, right-shift bit,
			# and repeat.  If a bit is present in any location in the mask attribute valuye, then add that 
			# usage mask to the variable L_UsageMask.  Once you have iterated across all bit positions in the mask, 
			# then convert the list of cryptographic usage methods (L_UsageMask) to a tuple for association
			# with the key.  Whew!
			
				bitLen = len(enums.CryptographicUsageMask)
				m_bit = 2**(bitLen)
				for bb in range(bitLen):
					bit_test = m_bit & d.attribute_value.value
					if (bit_test > 0):
						L_UsageMask.append(enums.CryptographicUsageMask(bit_test))
					m_bit = m_bit >> 1
				C_UsageMask = tuple(L_UsageMask)
			
			elif(str(d.attribute_name) == 'Cryptographic Length'):
				pass
			elif(str(d.attribute_name) == 'Cryptographic Algorithm'):
				pass
			elif(str(d.attribute_name) == 'State'):
				pass
			elif(str(d.attribute_name) == 'Operation Policy Name'):
				pass
			elif(str(d.attribute_name) == 'Object Type'):
				pass
			else:
				d.attribute_value = None
	
			keyAttribIdx = keyAttribIdx + 1

# now push the keys to the destination KMIP key server

		tmpStr = str(keyValueDst[keyIdx])
		hexKey = bytes.fromhex(tmpStr[2:-1])
		
		symmetric_key = objects.SymmetricKey(
			enums.CryptographicAlgorithm.AES,
			256,
			hexKey,
			C_UsageMask,
			C_Name
		)
		
		# Upload the key, register the key, and activcate the key.
		try:
			kid = keyDest.register(symmetric_key)
			keyDest.activate(kid)

		except:
			print(" ... Key Registration and Activation Error - Check to ensure key does not already exist")
			
		keyIdx = keyIdx + 1
		
print("\n ---- key check  ---- ")

with keyDest:
	keyIdx = 0	#reset key index
#	listOfSrcKeys = keySource.locate(attributes=[keyAttribs])
	listOfDstKeys = keyDest.locate()		

# The first 'tuple object is just a LIST of key IDs.  However, the second object is a nested tubple of THREE key-valuye pairs 
# consisting of attribute_name, attribute_index, attribute_value, and attribute_value.  You can print(a) below to see a complete 
# list of this information (keys and values)

	keyCount = len(listOfDstKeys)
	print("\nNumber of Destination Keys: ", keyCount)
	
	for keyDstID in listOfDstKeys:
		# try:
			keyValueDst.insert(keyIdx, keyDest.get(keyDstID))

			keyAttribDst.insert(keyIdx, keyDest.get_attributes(keyDstID))
			
			tmpStr = str(keyValueDst[keyIdx])
			hexKey = hex(int("0x"+tmpStr[2:-1], 0))
			
			print("\nkeyIdx: ", keyIdx, "\n  keyDstID: ", keyDstID, "\n  keyValueDst[keyIdx]: ", hexKey)

			keyAttribIdx = 0
			for a in keyAttribDst[keyIdx][1]:
				
				#Get a more readable format of the digest
				if(str(a.attribute_name) == 'Digest'):
					a_value = a.attribute_value.digest_value.value.hex()
				else:
					a_value = a.attribute_value
					
				print("keyIdx: ", keyIdx, "keyAttribIdx: ", keyAttribIdx, a.attribute_name, ": ", a_value)
				keyAttribIdx = keyAttribIdx + 1
				
			keyIdx = keyIdx + 1
			
		#except:
			#print("\n KeyDstID: ", keyDstID, "\n  KEY READ ERROR - Value and Atribute")
		
print("\n --- END --- ")



