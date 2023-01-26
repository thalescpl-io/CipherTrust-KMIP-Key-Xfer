REM
REM kc.py KMIP Key Transfer batch file with values
REM
copy /b T_CA*.pem TrustedCAs.pem
py kc.py -srcHost cm-spock.test256.io -srcUser User-KMIP-Bones -srcPass Photon-1 -dstHost cm-kirk.test256.io -dstUser User-KMIP-Sulu -dstPass Photon-2 -clientCert kmip_client.crt -clientKey kmip_client.key -trustedCAs TrustedCAs.pem

