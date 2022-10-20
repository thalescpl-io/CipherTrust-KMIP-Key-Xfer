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


# Specify key source KMIP Server and attributes
keySource =	client.ProxyKmipClient(
			hostname='192.168.1.184',
			port='5696',
			cert='kmipclient.crt',
			key='kmipclient.key',
			ca='TrustedCAs.pem',
#			cert_reqs=ssl.CERT_OPTIONAL, # no longer supported although you may see this in the default pykmip.conf file, if used.
			ssl_version="PROTOCOL_TLSv1_2",
			username='kmip_user',
			password='Guardium123!',
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
			username='kmip_user',
			password='Guardium123!',
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
keyAttribIdx 	= 0
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
with keySource:
	listOfSrcKeys = keySource.locate(attributes=[keyAttribs])	

# The first 'tuple object is just a LIST of key IDs.  However, the second object is a nested tubple of THREE key-valuye pairs 
# consisting of attribute_name, attribute_index, attribute_value, and attribute_value.  You can print(a) below to see a complete 
# list of this information (keys and values)

	keyCount = len(listOfSrcKeys)
	print("\nNumber of Src Keys: ", keyCount, "\n")
	
	for keySrcID in listOfSrcKeys:
		keyValueSrc.insert(keyIdx, keySource.get(keySrcID))
		keyValueDst.insert(keyIdx, keyValueSrc[keyIdx]) 	# make a copy

		keyAttribSrc.insert(keyIdx, keySource.get_attributes(keySrcID))
		keyAttribDst.insert(keyIdx, keyAttribSrc[keyIdx])	# make a copy
		
		print("\nkeyIdx: ", keyIdx, "\keySrcID: ", keySrcID, "keyValueSrc[keyIdx]: ", keyValueSrc[keyIdx])
		
		keyAttribIdx = 0
		for a in keyAttribSrc[keyIdx][1]:
			print("keyIdx: ", keyIdx, "keyAttribIdx: ", keyAttribIdx, a.attribute_name, ": ", a.attribute_value)
			keyAttribIdx = keyAttribIdx + 1
		
		keyIdx = keyIdx + 1

# The following duplication contains everything EXCEPT the keyID (which needs to be different)
# keyAttribDst = keyAttribSrc

print("\n ---- key copying ---- ")


with keyDest:
	keyIdx = 0	#reset key index

	
	while (keyIdx < keyCount):
		keyAttribIdx = 0
		
		print("\n keyID: ", keyAttribDst[keyIdx][0] )
		
		for d in keyAttribDst[keyIdx][1]:
			if(str(d.attribute_name) == 'Name'):
				d.attribute_value = str(d.attribute_value) + "_V2"
				C_Name = d.attribute_value
			elif(str(d.attribute_name) == 'Cryptographic Usage Mask'):
		
		# Magic method for deconstructing usage mask...
				L_UsageMask = []
				bitLen = len(enums.CryptographicUsageMask)
				m_bit = 2**(bitLen)
				for bb in range(bitLen):
					bit_test = m_bit & d.attribute_value.value
					if (bit_test > 0):
						print(bb, bit_test)
						print(enums.CryptographicUsageMask(bit_test))
						L_UsageMask.append(enums.CryptographicUsageMask(bit_test))
						C_UsageMask = tuple(L_UsageMask)
					m_bit = m_bit >> 1
			
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
				# keyAttribDst[keyIdx][1].remove(d)

			print("keyIdx: ", keyIdx, "keyAttribIdx: ", keyAttribIdx, d.attribute_name, ": ", d.attribute_value)
			
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
		# kid = keyDest.register(symmetric_key)
			
		keyIdx = keyIdx + 1
		

