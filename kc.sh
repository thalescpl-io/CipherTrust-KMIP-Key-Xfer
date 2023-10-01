# !/bin/bash
#
# Script for executing kc.by on Linux
#
cat T_CA*.pem > TrustedCAs.pem

python3 kc.py \
-srcHost 192.168.1.180 \
-dstHost 192.168.1.190 \
-dstUser kmip_alice -dstPass Thales123! \
-clientCert KMIP-Alice.crt -clientKey KMIP-Alice-key.pem \
-trustedCAs TrustedCAs.pem
