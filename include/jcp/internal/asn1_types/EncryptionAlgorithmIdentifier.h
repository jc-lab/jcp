/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "PrivateKeyInfo"
 * 	found in "privatekeyinfo.asn1"
 * 	`asn1c -R`
 */

#ifndef	_EncryptionAlgorithmIdentifier_H_
#define	_EncryptionAlgorithmIdentifier_H_


#include <asn_application.h>

/* Including external dependencies */
#include "AlgorithmIdentifier.h"

#ifdef __cplusplus
extern "C" {
#endif

/* EncryptionAlgorithmIdentifier */
typedef AlgorithmIdentifier_t	 EncryptionAlgorithmIdentifier_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_EncryptionAlgorithmIdentifier;
asn_struct_free_f EncryptionAlgorithmIdentifier_free;
asn_struct_print_f EncryptionAlgorithmIdentifier_print;
asn_constr_check_f EncryptionAlgorithmIdentifier_constraint;
ber_type_decoder_f EncryptionAlgorithmIdentifier_decode_ber;
der_type_encoder_f EncryptionAlgorithmIdentifier_encode_der;
xer_type_decoder_f EncryptionAlgorithmIdentifier_decode_xer;
xer_type_encoder_f EncryptionAlgorithmIdentifier_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _EncryptionAlgorithmIdentifier_H_ */
#include <asn_internal.h>
