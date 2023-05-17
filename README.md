# KMIP-Client
 
The file *kc.py* is the "main" file for this application.  

The *pykmip.conf* file is an example configuration file and contains default locations for its residency within the file

All other files are supporting files (especially any .crt, .pem, or .key files)

kc.bat and kc.sh have also been created to simplify execution of the application and include all of the paramters.

usage: kc.py [-h] -srcHost SRCHOST [-srcPort SRCPORT] -srcUser SRCUSER -srcPass SRCPASS 
                  -dstHost DSTHOST [-dstPort DSTPORT] -dstUser DSTUSER -dstPass DSTPASS 
                  -clientCert CLIENTCERT -clientKey CLIENTKEY -trustedCAs TRUSTEDCAS
                  
                  
Note:  To clone this repository, login to GIT from your GIT client, then issue the followint command:
$ git clone https://github.com/RickT256/KMIP-Client
