# !/bin/bash
#
# Script for executing kc.by on Linux
#
cp T_CA*.pem TrustedCAs.pem

python3 kc.py \
-srcHost 192.168.1.180 \
-srcUser SKLMadmin -srcPass Thales_4567 \
-dstHost 192.168.1.190 \
-dstUser kmip_alice -dstPass Thales123! \
-clientCert KMIP-Alice.crt -clientKey KMIP-Alice-key.pem \
-trustedCAs TrustedCAs.pem
