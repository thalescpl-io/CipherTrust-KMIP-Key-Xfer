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

# Specify KMIP Server and attributes
c = client.ProxyKmipClient(
	hostname='192.168.1.184',
	port='5696',
	cert='kmipclient.crt',
	key='kmipclient.key',
	ca='TrustedCAs.pem',
#	cert_reqs=ssl.CERT_OPTIONAL, # no longer supported although you may see this in the default pykmip.conf file, if used.
	ssl_version="PROTOCOL_TLSv1_2",
	username='kmip_user',
	password='Guardium123!',
    config='client',
    config_file='pykmip.conf'	
)

# Alternative method for specifying KMIP Server.  Uses pykmip.conf file from default location.
#c = client.ProxyKmipClient()

# You need an attkibutes class defined for later use
f = attributes.AttributeFactory()
keyAttribs = f.create_attribute(
				enums.AttributeType.OBJECT_TYPE,
				enums.ObjectType.SYMMETRIC_KEY
			)

# Code for locating (READING) keys and associated attributes for user from KMIP server. It limits its search to those
# attributes defined by the create_attributes object.
# This call initiates connection with KMIP server
with c:
	listOfKeys = c.locate(attributes=[keyAttribs])	

# The first 'tuple object is just a LIST of key IDs.  However, the second object is a nested tubple of THREE key-valuye pairs 
# consisting of attribute_name, attribute_index, attribute_value, and attribute_value.  You can print(a) below to see a complete 
# list of this information (keys and values)

	print("\nNumber of Keys: ", len(listOfKeys), "\n")
	
	for keyID in listOfKeys:
		keyValue = c.get(keyID)
		convert_string_to_int = int(str(keyValue)[2:-1], base=16)
		convert_hex = hex(convert_string_to_int)
		print("\nkeyID: ", keyID, "\nKEY Value (hex): ", convert_hex )
		attriby = c.get_attributes(keyID)
		idx = 0
		for a in attriby[1]:
			print("Idx: ", idx, a.attribute_name, ": ", a.attribute_value)
			idx = idx + 1
	
