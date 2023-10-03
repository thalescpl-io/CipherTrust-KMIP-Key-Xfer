#####################################################################################
#
# 	Name: kcenums.py
# 	Author: Rick R
# 	Purpose: Enumerations for kc.py
#
#####################################################################################
from    kmip import enums

LIST_OF_KEY_ATTRIBUTES = [
    enums.AttributeType.UNIQUE_IDENTIFIER.value,
    enums.AttributeType.NAME.value, 
    enums.AttributeType.CRYPTOGRAPHIC_ALGORITHM.value, 
    enums.AttributeType.CRYPTOGRAPHIC_LENGTH.value,
    enums.AttributeType.CRYPTOGRAPHIC_USAGE_MASK.value,
    enums.AttributeType.OBJECT_TYPE.value,
    enums.AttributeType.STATE.value,
    enums.AttributeType.DIGEST.value
]

DEFAULT_KMIP_PORT = ["5696"]  # must be a list