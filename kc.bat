REM
REM kc.py KMIP Key Transfer batch file with values
REM
py kc.py -srcHost 192.168.1.184 -srcUser kmip_alice -srcPass Thales123! -dstHost 192.168.1.180 -dstUser kmip_charlie -dstPass Thales345! -clientCert kmip_client.crt -clientKey kmip_client.key -trustedCAs TrustedCAs.pem

