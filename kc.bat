REM
REM kc.py KMIP Key Transfer batch file with values
REM
copy /b T_CA*.pem TrustedCAs.pem
py kc.py -srcHost 192.168.1.180 -srcUser SKLMadmin -srcPass Thales_4567 -dstHost 192.168.1.190 -dstUser kmip_alice -dstPass Thales123! -clientCert KMIP-Alice.crt -clientKey KMIP-Alice-key.pem -trustedCAs TrustedCAs.pem

