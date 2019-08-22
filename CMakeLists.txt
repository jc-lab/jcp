cmake_minimum_required(VERSION 3.4)
project(jcp)

add_definitions(/MP)

set(CMAKE_CXX_STANDARD 11)

# Variables
# JCP_USE_MBEDCRYPTO
# JCP_USE_OPENSSL
# MBEDCRYPTO_INCLUDE_DIR
# MBEDCRYPTO_LIB

set(JCP_SRC_INCLUDE include/jcp/internal/asn1c/ANY.h include/jcp/internal/asn1c/asn_application.h include/jcp/internal/asn1c/asn_codecs.h include/jcp/internal/asn1c/asn_codecs_prim.h include/jcp/internal/asn1c/asn_internal.h include/jcp/internal/asn1c/asn_SET_OF.h include/jcp/internal/asn1c/asn_system.h include/jcp/internal/asn1c/ber_decoder.h include/jcp/internal/asn1c/ber_tlv_length.h include/jcp/internal/asn1c/ber_tlv_tag.h include/jcp/internal/asn1c/BIT_STRING.h include/jcp/internal/asn1c/constraints.h include/jcp/internal/asn1c/constr_CHOICE.h include/jcp/internal/asn1c/constr_SEQUENCE.h include/jcp/internal/asn1c/constr_SET_OF.h include/jcp/internal/asn1c/constr_TYPE.h include/jcp/internal/asn1c/der_encoder.h include/jcp/internal/asn1c/INTEGER.h include/jcp/internal/asn1c/NativeEnumerated.h include/jcp/internal/asn1c/NativeInteger.h include/jcp/internal/asn1c/OBJECT_IDENTIFIER.h include/jcp/internal/asn1c/OCTET_STRING.h include/jcp/internal/asn1c/per_decoder.h include/jcp/internal/asn1c/per_encoder.h include/jcp/internal/asn1c/per_opentype.h include/jcp/internal/asn1c/per_support.h include/jcp/internal/asn1c/xer_decoder.h include/jcp/internal/asn1c/xer_encoder.h include/jcp/internal/asn1c/xer_support.h include/jcp/internal/asn1_types/AlgorithmIdentifier.h include/jcp/internal/asn1_types/Attribute.h include/jcp/internal/asn1_types/Attributes.h include/jcp/internal/asn1_types/AttributeSetValue.h include/jcp/internal/asn1_types/ECParameters.h include/jcp/internal/asn1_types/ECPrivateKey.h include/jcp/internal/asn1_types/EncryptedData.h include/jcp/internal/asn1_types/EncryptedPrivateKeyInfo.h include/jcp/internal/asn1_types/EncryptionAlgorithmIdentifier.h include/jcp/internal/asn1_types/PrivateKey.h include/jcp/internal/asn1_types/PrivateKeyAlgorithmIdentifier.h include/jcp/internal/asn1_types/PrivateKeyInfo.h include/jcp/internal/asn1_types/PublicKeyInfo.h include/jcp/internal/asn1_types/RSAPrivateKey.h include/jcp/internal/asn1_types/RSAPublicKey.h include/jcp/internal/asn1_types/Version.h)
set(JCP_SRC_BASE src/cipher.cpp src/cipher_algo.cpp src/key_agreement.cpp src/key_agreement_algo.cpp src/mac.cpp src/mac_algo.cpp src/message_digest.cpp src/message_digest_algo.cpp src/provider.cpp src/secret_key_factory.cpp src/secret_key_factory_algo.cpp src/secure_random.cpp src/security.cpp src/signature.cpp src/signature_algo.cpp src/key_utils.cpp src/key_factory.cpp src/key_factory_algo.cpp src/big_integer.cpp src/x509_encoded_key_spec_impl.cpp src/pkcs8_encoded_key_spec_impl.cpp)
set(JCP_SRC_UTIL src/util/wrapped_big_integer.hpp)
set(JCP_SRC_ASN1C src/internal/asn1c/ANY.c src/internal/asn1c/asn1_object_identifier.c src/internal/asn1c/asn_codecs_prim.c src/internal/asn1c/asn_SET_OF.c src/internal/asn1c/ber_decoder.c src/internal/asn1c/ber_tlv_length.c src/internal/asn1c/ber_tlv_tag.c src/internal/asn1c/BIT_STRING.c src/internal/asn1c/constraints.c src/internal/asn1c/constr_CHOICE.c src/internal/asn1c/constr_SEQUENCE.c src/internal/asn1c/constr_SET_OF.c src/internal/asn1c/constr_TYPE.c src/internal/asn1c/der_encoder.c src/internal/asn1c/INTEGER.c src/internal/asn1c/NativeEnumerated.c src/internal/asn1c/NativeInteger.c src/internal/asn1c/OCTET_STRING.c src/internal/asn1c/per_decoder.c src/internal/asn1c/per_encoder.c src/internal/asn1c/per_opentype.c src/internal/asn1c/per_support.c src/internal/asn1c/xer_decoder.c src/internal/asn1c/xer_encoder.c src/internal/asn1c/xer_support.c)
set(JCP_SRC_ASN1C_TYPES src/internal/asn1_types/AlgorithmIdentifier.c src/internal/asn1_types/Attribute.c src/internal/asn1_types/Attributes.c src/internal/asn1_types/AttributeSetValue.c src/internal/asn1_types/ECParameters.c src/internal/asn1_types/ECPrivateKey.c src/internal/asn1_types/EncryptedData.c src/internal/asn1_types/EncryptedPrivateKeyInfo.c src/internal/asn1_types/EncryptionAlgorithmIdentifier.c src/internal/asn1_types/PrivateKey.c src/internal/asn1_types/PrivateKeyAlgorithmIdentifier.c src/internal/asn1_types/PrivateKeyInfo.c src/internal/asn1_types/PublicKeyInfo.c src/internal/asn1_types/RSAPrivateKey.c src/internal/asn1_types/RSAPublicKey.c src/internal/asn1_types/Version.c)
set(JCP_SRC_ASN1_X9 src/asn1/x9/x9_object_identifiers.cpp src/asn1/x9/x962_named_curves.cpp)
set(JCP_SRC_ASN1_SEC src/asn1/sec/sec_object_identifiers.cpp src/asn1/sec/sec_named_curves.cpp)
set(JCP_SRC_ASN1_PKCS8 src/asn1/pkcs8/pkcs8_object_identifiers.cpp)
set(JCP_SRC_ASN1_EDEC src/asn1/edec/edec_object_identifiers.cpp)
set(JCP_SRC_ASN1_TELETRUST src/asn1/teletrust/teletrust_object_identifiers.cpp)
set(JCP_SRC_SOFT src/soft/soft_hkdf_skf.cpp include/jcp/soft/soft_hkdf_skf.hpp src/soft/soft_pbkdf2_skf.cpp include/jcp/soft/soft_pbkdf2_skf.hpp)
set(JCP_SRC_INTERNAL src/internal/key_accessor.cpp src/internal/key_accessor.hpp)

include_directories(include)
include_directories(include/jcp/internal/asn1c)

add_library(jcp ${JCP_SRC_INCLUDE} ${JCP_SRC_BASE} ${JCP_SRC_UTIL} ${JCP_SRC_ASN1C} ${JCP_SRC_ASN1C_TYPES} ${JCP_SRC_ASN1_X9} ${JCP_SRC_ASN1_SEC} ${JCP_SRC_ASN1_PKCS8} ${JCP_SRC_ASN1_EDEC} ${JCP_SRC_ASN1_TELETRUST} ${JCP_SRC_INTERNAL} ${JCP_SRC_SOFT})

IF(${JCP_USE_OPENSSL})
    add_subdirectory(provider/openssl)
ENDIF()
IF(${JCP_USE_MBEDCRYPTO})
    add_subdirectory(provider/mbedcrypto)
ENDIF()

add_subdirectory(example)
