REM
REM kc.py KMIP Key Transfer batch file with values
REM
copy /b T_CA*.pem TrustedCAs.pem
py kc.py -srcHost gde-sun.test256.io -srcUser kmip_alice -srcPass Thales123! -dstHost cm-spock.test256.io -dstUser kmip_bob -dstPass Thales234! -clientCert kmip_client.crt -clientKey kmip_client.key -trustedCAs TrustedCAs.pem

