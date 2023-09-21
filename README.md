# KMIP-Client
 
The file *kc.py* is the "main" file for this application.  

The *pykmip.conf* file is an example configuration file and contains default locations for its residency within the file

All other files are supporting files (especially any .crt, .pem, or .key files)

kc.bat and kc.sh have also been created to simplify execution of the application and include all of the paramters.

usage: **kc.py [-h] -srcHost SRCHOST [-srcPort SRCPORT]  
                  -dstHost DSTHOST [-dstPort DSTPORT] -dstUser DSTUSER -dstPass DSTPASS 
                  -clientCert CLIENTCERT -clientKey CLIENTKEY -trustedCAs TRUSTEDCAS**
                  
                  
Notes:  
a) The pem file that contains the list of CAs that the application needs to trust is provide by the TRIUSTEDCAS file.  However, the CAs that need to be trusted can vary on a deployment by deploymet basis especially since the default CA for CipherTrust is unique to each instance of CipherTrust.  As such, I recommend downloading all CAs at the party (for the source and destination KMIP servers) into the same folder as kc.py and then concatenating them into a single file.  In the repository, I provide a number of CAs that I have used in testing and labled them "T_CAx.pem" where "x" is a number nad then I concat all of those file into the file called "TrustedCAs.pem"
 - For Windows, the concatination command is:  **copy /b T_CA\*.pem TrustedCAs.pem**
 - For Linux, the concatination command is: **cp T_CA\*.pem TrustedCAs.pem**

b) The distination user (DSTUSR) musts be a member of the KEY USERS administrative group. 

c) The source user (SRCUSR) must be the OWNER of the KMIP keys that are to be exported.  This branch of the code assumes the source is GKLM and has been customized accordingly.

d) The keys that are to be exported via the KMIP interface from the source host (SRCHOST) must be EXPORTABLE (check flag)

e) The KMIP library comes from PYKMIP.  You can find their documentation here: https://pykmip.readthedocs.io/en/latest/client.html

f) Opensource informaton for PyKMIP can be found here:  https://github.com/OpenKMIP/PyKMIP

g) In some instances, you may get an error pertaining to ORIGINAL_CREATION_DATE.  The solution to this is found in the following link and will require the user to edit their own attribute_values.py file which is part of the pykmip package (a dependency of this code).  https://github.com/OpenKMIP/PyKMIP/issues/628

**DISCLAIMER**:  Private keys provided in this repository *should be considered compromised.* They are included for *demonstration and educational purposes only* and should *NOT* be used in a production environment.
