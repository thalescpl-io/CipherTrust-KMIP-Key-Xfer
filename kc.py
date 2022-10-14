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

# Code for creating a key and writing it to the KMIP Server

# Creates New Symmetric Key on KMIP Server
#with c:
#	key_id = c.create(
#    	enums.CryptographicAlgorithm.AES,
#        256,
#        operation_policy_name='default',
#        name='Test_256_AES_Symmetric_Key',
#        cryptographic_usage_mask=[
#            enums.CryptographicUsageMask.ENCRYPT,
#            enums.CryptographicUsageMask.DECRYPT
#        ]
#    )
#	print("Witten - Key ID:", key_id)

# Code for reading keys and associated attributes for user from KMIP server

with c:
	keylist = c.locate(
		attributes=[
			f.create_attribute(
				enums.AttributeType.OBJECT_TYPE,
				enums.ObjectType.SYMMETRIC_KEY
			)
		]
	)	
	print(keylist)
	
	for keyID in keylist:
		attriby = c.get_attributes(keyID)
		print("\nkeyID: ", keyID)
		kkey = c.get(keyID)
		print("KEY: ", kkey)
		for a in attriby[1]:
			print(a.attribute_name, ": ", a.attribute_value)
	
