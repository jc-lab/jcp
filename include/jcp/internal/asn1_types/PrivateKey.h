/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "PrivateKeyInfo"
 * 	found in "PublicKeyInfo.asn"
 * 	`asn1c -R`
 */

#ifndef	_PrivateKey_H_
#define	_PrivateKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OCTET_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PrivateKey */
typedef OCTET_STRING_t	 PrivateKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PrivateKey;
asn_struct_free_f PrivateKey_free;
asn_struct_print_f PrivateKey_print;
asn_constr_check_f PrivateKey_constraint;
ber_type_decoder_f PrivateKey_decode_ber;
der_type_encoder_f PrivateKey_encode_der;
xer_type_decoder_f PrivateKey_decode_xer;
xer_type_encoder_f PrivateKey_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _PrivateKey_H_ */
#include <asn_internal.h>
