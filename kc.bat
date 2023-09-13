REM
REM kc.py KMIP Key Transfer batch file with values
REM
copy /b T_CA*.pem TrustedCAs.pem
py kc.py -srcHost gklm.test256.io -srcUser SKLMadmin -srcPass Thales_4567 -dstHost cm-kirk.test256.io -dstUser kmip_alice -dstPass Thales123! -clientCert KMIP-Alice.crt -clientKey KMIP-Alice-key.pem -trustedCAs TrustedCAs.pem

